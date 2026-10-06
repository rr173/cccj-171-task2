"""HTTP API: policy administration, login, signal ingestion, re-auth,
attestation renewal, termination, per-request adjudication, session state,
and append-only audit inspection.

Served with the Python standard library only.  A session is presented by its
bearer token; the audit and state pages also accept ?token=.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

from .store import SessionTerminated, Store, StoreError
from .ui import INDEX_HTML

DEFAULT_DB = "zta.db"


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "ZTA-Risk/1.0"

    # injected by make_server
    store: Store

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    # ------------------------------------------------------------- plumbing

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str, status: int = 200) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise StoreError(f"invalid JSON body: {exc}", 400) from exc
        if not isinstance(data, dict):
            raise StoreError("JSON body must be an object", 400)
        return data

    def _query(self) -> dict[str, str]:
        q = parse_qs(urlparse(self.path).query)
        return {k: v[-1] for k, v in q.items()}

    def _bearer(self, data: dict[str, Any]) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        token = data.get("token") or self._query().get("token")
        if not token:
            raise StoreError("missing bearer token", 401)
        return token

    def _actor(self, data: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Resolve the trusted administrative actor.

        In this no-dependency reference deployment identity and roles are passed
        by API gateway headers (X-User-Id / X-User-Roles), with body fallback for
        local testing.  Real deployments should populate these behind an
        authenticated edge proxy.
        """
        data = data or {}
        actor_id = (
            self.headers.get("X-User-Id")
            or data.get("actor_id")
            or (data.get("actor") or {}).get("id")
        )
        if not actor_id:
            raise StoreError("missing X-User-Id actor", 401, "unauthorized")
        raw_roles = self.headers.get("X-User-Roles")
        if raw_roles is None:
            actor = data.get("actor") or {}
            if isinstance(actor, dict) and "roles" in actor:
                raw_roles = actor.get("roles")
            else:
                raw_roles = data.get("actor_roles", data.get("role"))
        if isinstance(raw_roles, str):
            roles = [r.strip() for r in raw_roles.split(",") if r.strip()]
        elif isinstance(raw_roles, (list, tuple)):
            roles = [str(r).strip() for r in raw_roles if str(r).strip()]
        else:
            roles = []
        return {"id": actor_id.strip(), "roles": roles}

    def _handle(self, fn: Callable[[], Any]) -> None:
        try:
            result = fn()
        except SessionTerminated as exc:
            self._send_json({"error": str(exc), "code": "session_terminated"}, exc.code)
        except StoreError as exc:
            payload = {"error": str(exc)}
            if getattr(exc, "error_code", None):
                payload["code"] = exc.error_code
            self._send_json(payload, exc.code)
        except Exception as exc:  # never leak a stack trace over HTTP
            self._send_json({"error": f"internal error: {exc}"}, 500)
        else:
            if result is not None:
                self._send_json(result)

    def _require_draft_reader(self) -> dict[str, Any]:
        actor = self._actor()
        roles = set(actor["roles"])
        if "admin" not in roles and "approver" not in roles:
            raise StoreError(
                "actor is not authorized to view policy drafts",
                403,
                "forbidden",
            )
        return actor

    # ------------------------------------------------------------------ GET

    def do_GET(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"

        if path == "/":
            return self._handle(lambda: self._send_html(INDEX_HTML))

        if path == "/api/health":
            return self._handle(
                lambda: {"status": "ok", "policy_version": self.store.latest_policy_version()}
            )

        if path == "/api/policies":
            return self._handle(lambda: {"policies": self.store.list_policies()})

        if path in ("/api/policy-drafts", "/api/policies/drafts"):
            status = self._query().get("status")

            def drafts() -> dict[str, Any]:
                self._require_draft_reader()
                return {"drafts": self.store.list_policy_drafts(status=status)}

            return self._handle(drafts)

        if path.startswith(("/api/policy-drafts/", "/api/policies/drafts/")):
            draft_id, operation = self._draft_route_parts(path)
            if operation:
                return self._send_json({"error": f"not found: {path}"}, 404)

            def one_draft() -> dict[str, Any]:
                self._require_draft_reader()
                return self.store.get_policy_draft(draft_id)

            return self._handle(one_draft)

        if path == "/api/sessions":
            return self._handle(lambda: {"sessions": self.store.list_sessions()})

        if path == "/api/session":
            def show() -> dict[str, Any]:
                token = self._query().get("token")
                if not token:
                    auth = self.headers.get("Authorization", "")
                    token = auth[7:].strip() if auth.startswith("Bearer ") else ""
                if not token:
                    raise StoreError("missing token", 401)
                return self.store.get_session_by_token(token)
            return self._handle(show)

        if path == "/api/events":
            def events() -> dict[str, Any]:
                q = self._query()
                sid = q.get("session_id")
                if not sid:
                    token = q.get("token")
                    auth = self.headers.get("Authorization", "")
                    if not token and auth.startswith("Bearer "):
                        token = auth[7:].strip()
                    if not token:
                        raise StoreError("session_id or token required", 400)
                    sid = self.store.get_session_by_token(token)["id"]
                return {"session_id": sid, "events": self.store.list_events(sid)}
            return self._handle(events)

        if path == "/api/audit":
            def audit() -> dict[str, Any]:
                q = self._query()
                sid = q.get("session_id")
                if not sid:
                    token = q.get("token")
                    auth = self.headers.get("Authorization", "")
                    if not token and auth.startswith("Bearer "):
                        token = auth[7:].strip()
                    if token:
                        sid = self.store.get_session_by_token(token)["id"]
                limit = int(q.get("limit", "100"))
                rows = self.store.list_audit(sid, limit)
                for r in rows:
                    r["allowed"] = bool(r["allowed"])
                    r["detail"] = json.loads(r["detail"])
                return {"audit": rows}
            return self._handle(audit)

        self._send_json({"error": f"not found: {path}"}, 404)

    # ----------------------------------------------------------------- POST

    def do_POST(self) -> None:
        path = urlparse(self.path).path.rstrip("/")
        try:
            data = self._read_json()
        except StoreError as exc:
            return self._send_json({"error": str(exc)}, exc.code)

        if path == "/api/login":
            def action() -> dict[str, Any]:
                return self.store.login(
                    user_id=data["user_id"],
                    role=data["role"],
                    country=data.get("country"),
                    device_id=data["device_id"],
                    attest_level=int(data.get("attest_level", 0)),
                    attest_nonce=int(data.get("attest_nonce", 1)),
                    attest_valid_seconds=data.get("attest_valid_seconds", 3600),
                )
            return self._handle(action)

        if path == "/api/policies":
            return self._post_policy_draft(data)

        if path in ("/api/policy-drafts", "/api/policies/drafts"):
            return self._post_policy_draft(data)

        if path.startswith(("/api/policy-drafts/", "/api/policies/drafts/")):
            draft_id, operation = self._draft_route_parts(path)
            if operation == "approve":
                return self._approve_policy_draft(draft_id, data)
            if operation == "reject":
                return self._reject_policy_draft(draft_id, data)
            if operation == "withdraw":
                return self._withdraw_policy_draft(draft_id, data)
            return self._send_json({"error": f"not found: {path}"}, 404)

        if path == "/api/signals":
            def action() -> dict[str, Any]:
                sid = data.get("session_id") or self.store.get_session_by_token(
                    self._bearer(data)
                )["id"]
                return self.store.ingest_signal(
                    session_id=sid,
                    signal=data["signal"],
                    observed_at=data.get("observed_at"),
                    source=data.get("source"),
                    detail=data.get("detail"),
                )
            return self._handle(action)

        if path == "/api/reauth":
            def action() -> dict[str, Any]:
                sid = data.get("session_id") or self.store.get_session_by_token(
                    self._bearer(data)
                )["id"]
                return self.store.reauthenticate(
                    session_id=sid,
                    nonce=int(data["nonce"]),
                    observed_at=data.get("observed_at"),
                    clear=data.get("clear"),
                )
            return self._handle(action)

        if path == "/api/attestation":
            def action() -> dict[str, Any]:
                sid = data.get("session_id") or self.store.get_session_by_token(
                    self._bearer(data)
                )["id"]
                return self.store.update_attestation(
                    session_id=sid,
                    level=int(data["level"]),
                    nonce=int(data["nonce"]),
                    observed_at=data.get("observed_at"),
                    valid_seconds=data.get("valid_seconds", 3600),
                )
            return self._handle(action)

        if path == "/api/terminate":
            def action() -> dict[str, Any]:
                sid = data.get("session_id") or self.store.get_session_by_token(
                    self._bearer(data)
                )["id"]
                return self.store.terminate(
                    sid,
                    reason=data.get("reason", "manual_termination"),
                    observed_at=data.get("observed_at"),
                )
            return self._handle(action)

        if path == "/api/decide":
            def action() -> dict[str, Any]:
                token = self._bearer(data)
                d = self.store.decide(
                    token=token,
                    resource=data["resource"],
                    action=data["action"],
                    country=data.get("country"),
                    observed_at=data.get("observed_at"),
                )
                return {
                    "allowed": d.allowed,
                    "reason": d.reason,
                    "policy_version": d.policy_version,
                    "watermark": d.watermark,
                    "audit_id": d.audit_id,
                }
            return self._handle(action)

        self._send_json({"error": f"not found: {path}"}, 404)

    def _post_policy_draft(self, data: dict[str, Any]) -> None:
        def action() -> dict[str, Any]:
            body = data.get("policy") if isinstance(data.get("policy"), dict) else data
            base = data.get("base_version")
            draft = self.store.submit_policy_draft(
                body,
                self._actor(data),
                base_version=int(base) if base is not None else None,
            )
            return {"submitted": True, "draft": draft}
        self._handle(action)

    def _draft_route_parts(self, path: str) -> tuple[str, str]:
        for prefix in ("/api/policy-drafts/", "/api/policies/drafts/"):
            if path.startswith(prefix):
                rest = path[len(prefix) :]
                if "/" in rest:
                    draft_id, operation = rest.split("/", 1)
                    return draft_id, operation
                return rest, ""
        raise StoreError(f"not found: {path}", 404)

    def _approve_policy_draft(self, draft_id: str, data: dict[str, Any]) -> None:
        def action() -> dict[str, Any]:
            expected = data.get("expected_version")
            draft = self.store.approve_policy_draft(
                draft_id,
                self._actor(data),
                confirm_diff=bool(data.get("confirm_diff")),
                expected_version=int(expected) if expected is not None else None,
            )
            return {
                "approved": True,
                "idempotent": bool(draft.get("idempotent")),
                "draft": draft,
            }
        self._handle(action)

    def _reject_policy_draft(self, draft_id: str, data: dict[str, Any]) -> None:
        def action() -> dict[str, Any]:
            draft = self.store.reject_policy_draft(
                draft_id,
                self._actor(data),
                reason=str(data.get("reason", "rejected")),
            )
            return {"rejected": True, "draft": draft}
        self._handle(action)

    def _withdraw_policy_draft(self, draft_id: str, data: dict[str, Any]) -> None:
        def action() -> dict[str, Any]:
            draft = self.store.withdraw_policy_draft(
                draft_id,
                self._actor(data),
                reason=str(data.get("reason", "withdrawn")),
            )
            return {"withdrawn": True, "draft": draft}
        self._handle(action)


def make_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    db_path: str = DEFAULT_DB,
    verbose: bool = False,
) -> ThreadingHTTPServer:
    store = Store(db_path)
    handler = ApiHandler
    handler.store = store
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.verbose = verbose
    httpd.store = store  # keep a reference so callers can close it
    return httpd
