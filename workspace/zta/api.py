"""HTTP API: policy administration, login, signal ingestion, re-auth,
attestation renewal, termination, per-request adjudication, session state,
and append-only audit inspection.

Served with the Python standard library only.  A session is presented by its
bearer token; the audit and state pages also accept ?token=.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
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

    def _handle(self, fn: Callable[[], Any]) -> None:
        try:
            result = fn()
        except SessionTerminated as exc:
            payload: dict[str, Any] = {"error": str(exc), "code": "session_terminated"}
            self._send_json(payload, exc.code)
        except StoreError as exc:
            payload = {"error": str(exc)}
            if exc.code_name:
                payload["code"] = exc.code_name
            if exc.extra:
                payload.update(exc.extra)
            self._send_json(payload, exc.code)
        except Exception as exc:  # never leak a stack trace over HTTP
            self._send_json({"error": f"internal error: {exc}"}, 500)
        else:
            if result is not None:
                self._send_json(result)

    def _operator(self, data: dict[str, Any]) -> str:
        op = self.headers.get("X-Operator-ID", "")
        if not op:
            op = str(data.get("operator") or "").strip()
        return op.strip()

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

        if path == "/api/policy-drafts":
            def list_drafts() -> dict[str, Any]:
                status = self._query().get("status")
                return {"drafts": self.store.list_drafts(status=status)}
            return self._handle(list_drafts)

        if path.startswith("/api/policy-drafts/"):
            draft_id = path.rsplit("/", 1)[-1]
            return self._handle(
                lambda: self.store.get_draft(draft_id, include_events=True)
            )

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
            # Policy changes now enter the four-eyes draft workflow first.
            def deprecated_publish() -> dict[str, Any]:
                raise StoreError(
                    "direct policy publishing is disabled: submit a draft via "
                    "POST /api/policy-drafts and have it approved "
                    "(POST /api/policy-drafts/<id>/approve)",
                    403,
                    "draft_required",
                )
            return self._handle(deprecated_publish)

        if path == "/api/policy-drafts":
            def submit() -> dict[str, Any]:
                policy_body = data.get("policy", data)
                return self.store.submit_draft(
                    body=policy_body,
                    operator=self._operator(data),
                    ttl_seconds=data.get("ttl_seconds"),
                    base_version=data.get("base_version"),
                )
            return self._handle(submit)

        if path.endswith("/approve") and "/policy-drafts/" in path:
            def approve() -> dict[str, Any]:
                draft_id = path.split("/")[3]
                return self.store.approve_draft(
                    draft_id=draft_id,
                    operator=self._operator(data),
                    diff_digest=data.get("diff_digest"),
                )
            return self._handle(approve)

        if path.endswith("/reject") and "/policy-drafts/" in path:
            def reject() -> dict[str, Any]:
                draft_id = path.split("/")[3]
                return self.store.reject_draft(
                    draft_id=draft_id,
                    operator=self._operator(data),
                    reason=str(data.get("reason") or "rejected"),
                )
            return self._handle(reject)

        if path.endswith("/withdraw") and "/policy-drafts/" in path:
            def withdraw() -> dict[str, Any]:
                draft_id = path.split("/")[3]
                return self.store.withdraw_draft(
                    draft_id=draft_id,
                    operator=self._operator(data),
                    reason=str(data.get("reason") or "withdrawn"),
                )
            return self._handle(withdraw)

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
