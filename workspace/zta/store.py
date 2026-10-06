"""Session state machine and durable storage.

Concurrency model
-----------------
Every state mutation of a session is serialised by two barriers:

1. An in-process ``threading.Lock`` keyed by session id (the *single session
   watermark* lock).
2. A SQLite ``BEGIN IMMEDIATE`` transaction, so multi-process deployments and
   the append-only event/audit journals are also serialised.

Inside that critical section the event receives the next per-session ``seq`` --
a strictly monotonic watermark.  Old / out-of-order signals are detected by the
source's last ``observed_at`` (and monotonic nonces for re-authentication and
attestation): they are journaled with ``accepted=0``, do *not* consume a
watermark slot, and never mutate state.

Monotonicity of privilege
-------------------------
* The authorisation *ceiling* is computed once at login against the initial
  policy version and stored as a concrete allow list; later policy upgrades can
  only be intersected with it, never widen it.
* The revocation set is grow-only; re-authentication and fresh attestation
  clear *gates*, they never remove revivals.
* ``terminated`` is the greatest element of a small status lattice; nothing
  resurrects a terminated session.
"""

from __future__ import annotations

import fnmatch
import json
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from .policy import Policy, default_policy_v1
from .policy import ATTESTATION, REAUTH, REVOKE, TERMINATE


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)


class StoreError(Exception):
    """Base error; ``code`` mirrors an HTTP status for the API layer."""

    def __init__(self, message: str, code: int = 400):
        super().__init__(message)
        self.code = code


class SessionTerminated(StoreError):
    def __init__(self):
        super().__init__("session is terminated", 409)


@dataclass
class Decision:
    allowed: bool
    reason: str
    policy_version: int
    watermark: int
    audit_id: Optional[int]


class Store:
    def __init__(self, path: str = ":memory:", clock=utcnow):
        self._clock = clock
        self._conn = sqlite3.connect(
            path,
            check_same_thread=False,
            isolation_level=None,  # we manage transactions explicitly
            timeout=15,  # retry BEGIN IMMEDIATE under contention
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._locks_lock = threading.Lock()
        self._session_locks: dict[str, threading.Lock] = {}
        self._init_schema()
        self._seed()

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------ infra

    def _lock_for(self, session_id: str) -> threading.Lock:
        with self._locks_lock:
            lock = self._session_locks.get(session_id)
            if lock is None:
                lock = threading.Lock()
                self._session_locks[session_id] = lock
            return lock

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS policies (
                version      INTEGER PRIMARY KEY,
                body         TEXT NOT NULL,
                published_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id                 TEXT PRIMARY KEY,
                token              TEXT UNIQUE NOT NULL,
                user_id            TEXT NOT NULL,
                role               TEXT NOT NULL,
                initial_policy_v   INTEGER NOT NULL,
                current_policy_v   INTEGER NOT NULL,
                country            TEXT,
                device_id          TEXT NOT NULL,
                attest_level       INTEGER NOT NULL,
                attest_nonce       INTEGER NOT NULL,
                attest_issued_at   TEXT NOT NULL,
                attest_valid_until TEXT,
                reauth_nonce       INTEGER NOT NULL DEFAULT 0,
                watermark          INTEGER NOT NULL DEFAULT 0,
                status             TEXT NOT NULL DEFAULT 'active',
                ceiling            TEXT NOT NULL,
                revocations        TEXT NOT NULL DEFAULT '[]',
                gates              TEXT NOT NULL DEFAULT '[]',
                last_signal_at     TEXT,
                created_at         TEXT NOT NULL
            );

            -- append-only journal of every risk/event ingestion attempt
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT NOT NULL,
                seq         INTEGER,            -- NULL when rejected/stale
                kind        TEXT NOT NULL,
                source      TEXT,
                observed_at TEXT,
                accepted    INTEGER NOT NULL,
                detail      TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );

            -- append-only per-request adjudication audit
            CREATE TABLE IF NOT EXISTS audit (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id     TEXT NOT NULL,
                seq_watermark  INTEGER NOT NULL,
                policy_version INTEGER NOT NULL,
                resource       TEXT NOT NULL,
                action         TEXT NOT NULL,
                allowed        INTEGER NOT NULL,
                reason         TEXT NOT NULL,
                detail         TEXT NOT NULL,
                decided_at     TEXT NOT NULL
            );
            """
        )

    def _seed(self) -> None:
        row = self._conn.execute("SELECT MAX(version) AS v FROM policies").fetchone()
        if row["v"] is None:
            body = default_policy_v1()
            self._conn.execute(
                "INSERT INTO policies(version, body, published_at) VALUES (?,?,?)",
                (body["version"], json.dumps(body), iso(self._clock())),
            )

    # ------------------------------------------------------------- policies

    def publish_policy(self, body: dict[str, Any]) -> Policy:
        policy = Policy.from_dict(body)
        now = iso(self._clock())
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute(
                "SELECT MAX(version) AS v FROM policies"
            ).fetchone()
            if row["v"] is not None and policy.version <= row["v"]:
                self._conn.execute("ROLLBACK")
                raise StoreError(
                    f"policy version must be > {row['v']} (new versions are immutable)",
                    409,
                )
            self._conn.execute(
                "INSERT INTO policies(version, body, published_at) VALUES (?,?,?)",
                (policy.version, json.dumps(policy.body), now),
            )
            self._conn.execute("COMMIT")
        except sqlite3.Error as exc:
            self._safe_rollback()
            raise StoreError(f"database error: {exc}", 500) from exc
        # upgrade applies to *new* requests of live sessions, never retroactively
        self._conn.execute(
            "UPDATE sessions SET current_policy_v = ? WHERE status != 'terminated'",
            (policy.version,),
        )
        return policy

    def _get_policy(self, version: int) -> Policy:
        row = self._conn.execute(
            "SELECT body FROM policies WHERE version = ?", (version,)
        ).fetchone()
        if row is None:
            raise StoreError(f"policy version {version} not found", 404)
        return Policy.from_dict(json.loads(row["body"]))

    def latest_policy_version(self) -> int:
        return self._conn.execute("SELECT MAX(version) AS v FROM policies").fetchone()[
            "v"
        ]

    def list_policies(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT version, body, published_at FROM policies ORDER BY version"
        ).fetchall()
        return [
            {
                "version": r["version"],
                "published_at": r["published_at"],
                "policy": json.loads(r["body"]),
            }
            for r in rows
        ]

    # ---------------------------------------------------------------- login

    def login(
        self,
        user_id: str,
        role: str,
        country: Optional[str],
        device_id: str,
        attest_level: int,
        attest_nonce: int = 1,
        attest_valid_seconds: Optional[int] = 3600,
        ceiling_resources: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Establish a session bound to device proof, location, role and the
        initial policy version.  Fail closed when login-time constraints or
        credentials are not met."""
        if not user_id or not role or not device_id:
            raise StoreError("user_id, role and device_id are required")
        policy_version = self.latest_policy_version()
        policy = self._get_policy(policy_version)
        now = self._clock()

        if not policy.country_allowed(country):
            raise StoreError(
                f"login denied: country {country!r} outside allowed network locations",
                403,
            )
        if attest_level < policy.device_min_level():
            raise StoreError(
                f"login denied: device attestation level {attest_level} "
                f"< required {policy.device_min_level()}",
                403,
            )

        # Snapshot the *ceiling*: a concrete expansion of role allows under the
        # initial policy.  A later policy can only be intersected with it.
        patterns = self._ceiling_patterns(policy, role)
        if ceiling_resources is not None:
            patterns = [p for p in patterns if p["resource"] in ceiling_resources]
        valid_until = (
            iso(
                datetime.fromtimestamp(now.timestamp() + attest_valid_seconds, timezone.utc)
            )
            if attest_valid_seconds
            else None
        )

        sid = "sess_" + secrets.token_hex(12)
        token = secrets.token_urlsafe(24)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                """INSERT INTO sessions(
                    id, token, user_id, role, initial_policy_v, current_policy_v,
                    country, device_id, attest_level, attest_nonce,
                    attest_issued_at, attest_valid_until, reauth_nonce,
                    watermark, status, ceiling, revocations, gates, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,'active',?,'[]','[]',?)""",
                (
                    sid,
                    token,
                    user_id,
                    role,
                    policy_version,
                    policy_version,
                    country,
                    device_id,
                    attest_level,
                    attest_nonce,
                    iso(now),
                    valid_until,
                    0,
                    json.dumps(patterns),
                    iso(now),
                ),
            )
            self._journal(
                sid,
                1,
                "login",
                source=f"device:{device_id}",
                observed_at=iso(now),
                accepted=True,
                detail={
                    "role": role,
                    "country": country,
                    "attest_level": attest_level,
                    "policy_version": policy_version,
                    "ceiling_size": len(patterns),
                },
            )
            self._conn.execute("COMMIT")
        except sqlite3.Error as exc:
            self._safe_rollback()
            raise StoreError(f"database error: {exc}", 500) from exc
        return self.get_session(sid, token=token)

    @staticmethod
    def _ceiling_patterns(policy: Policy, role: str) -> list[dict[str, Any]]:
        """Materialise every role allow rule as concrete (resource, action)
        patterns.  Deny rules subtract patterns so the ceiling cannot contain
        access the initial policy never granted."""
        allows: list[dict[str, Any]] = []
        denies: list[dict[str, Any]] = []

        for rule in policy.body.get("rules", []):
            if role not in rule["roles"] and "*" not in rule["roles"]:
                continue
            for res in rule["resources"]:
                for act in rule["actions"]:
                    bucket = denies if rule["effect"] == "deny" else allows
                    bucket.append(
                        {
                            "resource": res,
                            "action": act,
                            "rule_id": rule.get("id"),
                        }
                    )
        return [
            a
            for a in allows
            if not any(
                d["resource"] == a["resource"] and d["action"] == a["action"]
                for d in denies
            )
        ]

    # ------------------------------------------------------------- lookups

    def get_session_by_token(self, token: str) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT id FROM sessions WHERE token = ?", (token,)
        ).fetchone()
        if row is None:
            raise StoreError("invalid session token", 401)
        return self.get_session(row["id"])

    def get_session(
        self, session_id: str, token: Optional[str] = None
    ) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if row is None:
            raise StoreError("session not found", 404)
        return self._session_view(row, include_token=token)

    def _session_view(self, row: sqlite3.Row, include_token: Optional[str] = None):
        data = {
            "id": row["id"],
            "user_id": row["user_id"],
            "role": row["role"],
            "initial_policy_version": row["initial_policy_v"],
            "current_policy_version": row["current_policy_v"],
            "country": row["country"],
            "device_id": row["device_id"],
            "attestation": {
                "level": row["attest_level"],
                "nonce": row["attest_nonce"],
                "issued_at": row["attest_issued_at"],
                "valid_until": row["attest_valid_until"],
            },
            "reauth_nonce": row["reauth_nonce"],
            "watermark": row["watermark"],
            "status": self._derive_status(row),
            "terminal": row["status"] == "terminated",
            "ceiling": json.loads(row["ceiling"]),
            "revocations": json.loads(row["revocations"]),
            "gates": json.loads(row["gates"]),
            "created_at": row["created_at"],
            "last_signal_at": row["last_signal_at"],
        }
        if include_token is not None:
            data["token"] = include_token
        return data

    def _derive_status(self, row: sqlite3.Row) -> str:
        if row["status"] == "terminated":
            return "terminated"
        gates = json.loads(row["gates"])
        if any(g.get("open") for g in gates):
            return "gated"
        return "active"

    def list_sessions(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM sessions ORDER BY created_at").fetchall()
        return [self._session_view(r) for r in rows]

    def list_events(self, session_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY id", (session_id,)
        ).fetchall()
        return [self._event_row(r) for r in rows]

    def list_audit(self, session_id: Optional[str] = None, limit: int = 100):
        if session_id:
            rows = self._conn.execute(
                "SELECT * FROM audit WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _event_row(r: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": r["id"],
            "session_id": r["session_id"],
            "seq": r["seq"],
            "kind": r["kind"],
            "source": r["source"],
            "observed_at": r["observed_at"],
            "accepted": bool(r["accepted"]),
            "detail": json.loads(r["detail"]),
            "recorded_at": r["recorded_at"],
        }

    # ------------------------------------------------------------- journal

    def _journal(
        self,
        session_id: str,
        seq: Optional[int],
        kind: str,
        *,
        source: Optional[str],
        observed_at: Optional[str],
        accepted: bool,
        detail: dict[str, Any],
    ) -> None:
        self._conn.execute(
            """INSERT INTO events
               (session_id, seq, kind, source, observed_at, accepted, detail, recorded_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                session_id,
                seq,
                kind,
                source,
                observed_at,
                1 if accepted else 0,
                json.dumps(detail, sort_keys=True),
                iso(self._clock()),
            ),
        )

    def _safe_rollback(self) -> None:
        try:
            self._conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    # ------------------------------------------------- risk signal ingestion

    def ingest_signal(
        self,
        session_id: str,
        signal: str,
        observed_at: Optional[str] = None,
        source: Optional[str] = None,
        detail: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Ingest one risk signal.  Signals only converge privilege."""
        source = source or signal
        obs_ts = self._coerce_observed(observed_at)
        with self._lock_for(session_id):
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT * FROM sessions WHERE id = ?", (session_id,)
                ).fetchone()
                if row is None:
                    self._conn.execute("ROLLBACK")
                    raise StoreError("session not found", 404)
                if row["status"] == "terminated":
                    self._journal(
                        session_id,
                        None,
                        "signal",
                        source=source,
                        observed_at=iso(obs_ts),
                        accepted=False,
                        detail={"signal": signal, "rejected": "session terminated"},
                    )
                    self._conn.execute("COMMIT")
                    raise SessionTerminated()

                # single watermark ordering: an older observation from the same
                # source is stale and must never undo a newer one's effect
                last = row["last_signal_at"]
                if last is not None:
                    prev_sources = self._max_observed_by_source(session_id)
                    prev = prev_sources.get(source)
                    if prev is not None and obs_ts <= prev:
                        self._journal(
                            session_id,
                            None,
                            "signal",
                            source=source,
                            observed_at=iso(obs_ts),
                            accepted=False,
                            detail={
                                "signal": signal,
                                "rejected": "stale_out_of_order",
                                "previous_observed_at": iso(prev),
                            },
                        )
                        self._conn.execute("COMMIT")
                        return self.get_session(session_id)

                policy = self._get_policy(row["current_policy_v"])
                rule = policy.signal_rule(signal)
                if rule is None:
                    # unknown signals fail closed as a re-authentication gate
                    action = REAUTH
                    rule = {"signal": signal, "action": REAUTH, "id": "fail-closed"}
                else:
                    action = rule["action"]

                seq = row["watermark"] + 1
                state = self._apply_signal(row, signal, rule, action, detail or {})
                self._persist_after_event(row, seq, state, last_signal=iso(obs_ts))
                self._journal(
                    session_id,
                    seq,
                    "signal",
                    source=source,
                    observed_at=iso(obs_ts),
                    accepted=True,
                    detail={
                        "signal": signal,
                        "rule_id": rule.get("id"),
                        "action": action,
                        **(detail or {}),
                    },
                )
                self._conn.execute("COMMIT")
            except StoreError:
                raise
            except sqlite3.Error as exc:
                self._safe_rollback()
                raise StoreError(f"database error: {exc}", 500) from exc
        return self.get_session(session_id)

    def _max_observed_by_source(self, session_id: str) -> dict[str, datetime]:
        rows = self._conn.execute(
            """SELECT source, MAX(observed_at) AS m
               FROM events
               WHERE session_id = ? AND accepted = 1 AND observed_at IS NOT NULL
               GROUP BY source""",
            (session_id,),
        ).fetchall()
        return {r["source"]: parse_iso(r["m"]) for r in rows}

    def _coerce_observed(self, observed_at: Optional[str]) -> datetime:
        if observed_at is None:
            return self._clock()
        try:
            dt = parse_iso(observed_at)
        except ValueError as exc:
            raise StoreError(f"bad observed_at: {observed_at}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _apply_signal(
        self,
        row: sqlite3.Row,
        signal: str,
        rule: dict[str, Any],
        action: str,
        detail: dict[str, Any],
    ) -> dict[str, Any]:
        revocations = json.loads(row["revocations"])
        gates = json.loads(row["gates"])
        status = row["status"]

        if action == TERMINATE:
            status = "terminated"
            # termination also closes every gate and seals the revocation set
            gates = [{**g, "open": False, "cleared_by": "termination"} for g in gates]
        elif action == REVOKE:
            for res in rule.get("resources", ["*"]):
                for act in rule.get("actions", ["*"]):
                    entry = {
                        "resource": res,
                        "action": act,
                        "signal": signal,
                        "rule_id": rule.get("id"),
                    }
                    if entry not in revocations:
                        revocations.append(entry)
        elif action in (REAUTH, ATTESTATION):
            gate = {
                "type": action,
                "signal": signal,
                "rule_id": rule.get("id"),
                "open": True,
                "opened_at": iso(self._clock()),
                "seq": row["watermark"] + 1,
                "detail": detail,
            }
            # one open gate per (type, signal); a repeat signal refreshes it
            gates = [g for g in gates if not (g["type"] == action and g["signal"] == signal)]
            gates.append(gate)
        return {"status": status, "revocations": revocations, "gates": gates}

    def _persist_after_event(
        self,
        row: sqlite3.Row,
        seq: int,
        state: dict[str, Any],
        *,
        last_signal: Optional[str] = None,
        attest: Optional[dict[str, Any]] = None,
        reauth_nonce: Optional[int] = None,
        country: Optional[str] = None,
    ) -> None:
        self._conn.execute(
            """UPDATE sessions SET
                 watermark = ?, status = ?, revocations = ?, gates = ?,
                 last_signal_at = COALESCE(?, last_signal_at),
                 attest_level = COALESCE(?, attest_level),
                 attest_nonce = COALESCE(?, attest_nonce),
                 attest_issued_at = COALESCE(?, attest_issued_at),
                 attest_valid_until = ?,
                 reauth_nonce = COALESCE(?, reauth_nonce),
                 country = COALESCE(?, country)
               WHERE id = ?""",
            (
                seq,
                state["status"],
                json.dumps(state["revocations"]),
                json.dumps(state["gates"]),
                last_signal,
                attest.get("level") if attest else None,
                attest.get("nonce") if attest else None,
                attest.get("issued_at") if attest else None,
                attest.get("valid_until") if attest else row["attest_valid_until"],
                reauth_nonce,
                country,
                row["id"],
            ),
        )

    # ------------------------------------------------------ re-authentication

    def reauthenticate(
        self,
        session_id: str,
        nonce: int,
        observed_at: Optional[str] = None,
        clear: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Fresh proof of identity.  Clears only reauth gates whose watermark is
        below this event; it can never touch revocations or termination."""
        obs_ts = self._coerce_observed(observed_at)
        with self._lock_for(session_id):
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._locked_session(session_id)
                if row["status"] == "terminated":
                    self._journal_reject(
                        session_id, "reauth", obs_ts, {"rejected": "session terminated"}
                    )
                    self._conn.execute("COMMIT")
                    raise SessionTerminated()
                if nonce <= row["reauth_nonce"]:
                    self._journal_reject(
                        session_id,
                        "reauth",
                        obs_ts,
                        {
                            "rejected": "stale_nonce",
                            "nonce": nonce,
                            "previous_nonce": row["reauth_nonce"],
                        },
                    )
                    self._conn.execute("COMMIT")
                    raise StoreError(
                        f"reauth nonce {nonce} is not newer than {row['reauth_nonce']}",
                        409,
                    )
                seq = row["watermark"] + 1
                gates = json.loads(row["gates"])
                clear_set = set(clear) if clear is not None else None
                cleared: list[dict[str, Any]] = []
                for g in gates:
                    if not g.get("open") or g["type"] != REAUTH:
                        continue
                    if clear_set is not None and g["signal"] not in clear_set:
                        continue
                    g["open"] = False
                    g["cleared_by"] = "reauth"
                    g["cleared_seq"] = seq
                    cleared.append(g["signal"])
                state = {
                    "status": row["status"],
                    "revocations": json.loads(row["revocations"]),
                    "gates": gates,
                }
                self._persist_after_event(
                    row, seq, state, reauth_nonce=nonce, last_signal=iso(obs_ts)
                )
                self._journal(
                    session_id,
                    seq,
                    "reauth",
                    source="user",
                    observed_at=iso(obs_ts),
                    accepted=True,
                    detail={"nonce": nonce, "cleared_gates": cleared},
                )
                self._conn.execute("COMMIT")
            except StoreError:
                raise
            except sqlite3.Error as exc:
                self._safe_rollback()
                raise StoreError(f"database error: {exc}", 500) from exc
        return self.get_session(session_id)

    # ------------------------------------------------------ attestation update

    def update_attestation(
        self,
        session_id: str,
        level: int,
        nonce: int,
        observed_at: Optional[str] = None,
        valid_seconds: Optional[int] = 3600,
    ) -> dict[str, Any]:
        """Renewed device proof.  Monotonic nonce blocks replay; a fresh proof
        clears attestation gates but cannot widen the login ceiling."""
        obs_ts = self._coerce_observed(observed_at)
        with self._lock_for(session_id):
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._locked_session(session_id)
                if row["status"] == "terminated":
                    self._journal_reject(
                        session_id,
                        "attestation",
                        obs_ts,
                        {"nonce": nonce, "rejected": "session terminated"},
                    )
                    self._conn.execute("COMMIT")
                    raise SessionTerminated()
                if nonce <= row["attest_nonce"]:
                    self._journal_reject(
                        session_id,
                        "attestation",
                        obs_ts,
                        {
                            "nonce": nonce,
                            "rejected": "stale_nonce",
                            "previous_nonce": row["attest_nonce"],
                        },
                    )
                    self._conn.execute("COMMIT")
                    raise StoreError(
                        f"attestation nonce {nonce} is not newer than {row['attest_nonce']}",
                        409,
                    )
                valid_until = (
                    iso(
                        datetime.fromtimestamp(
                            obs_ts.timestamp() + valid_seconds, timezone.utc
                        )
                    )
                    if valid_seconds
                    else None
                )
                seq = row["watermark"] + 1
                gates = json.loads(row["gates"])
                cleared: list[dict[str, Any]] = []
                for g in gates:
                    if g.get("open") and g["type"] == ATTESTATION:
                        g["open"] = False
                        g["cleared_by"] = "attestation"
                        g["cleared_seq"] = seq
                        cleared.append(g["signal"])
                state = {
                    "status": row["status"],
                    "revocations": json.loads(row["revocations"]),
                    "gates": gates,
                }
                attest = {
                    "level": level,
                    "nonce": nonce,
                    "issued_at": iso(obs_ts),
                    "valid_until": valid_until,
                }
                self._persist_after_event(
                    row, seq, state, attest=attest, last_signal=iso(obs_ts)
                )
                self._journal(
                    session_id,
                    seq,
                    "attestation",
                    source=f"device:{row['device_id']}",
                    observed_at=iso(obs_ts),
                    accepted=True,
                    detail={
                        "nonce": nonce,
                        "level": level,
                        "cleared_gates": cleared,
                    },
                )
                self._conn.execute("COMMIT")
            except StoreError:
                raise
            except sqlite3.Error as exc:
                self._safe_rollback()
                raise StoreError(f"database error: {exc}", 500) from exc
        return self.get_session(session_id)

    def _locked_session(self, session_id: str) -> sqlite3.Row:
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if row is None:
            self._conn.execute("ROLLBACK")
            raise StoreError("session not found", 404)
        return row

    def _journal_reject(
        self, session_id: str, kind: str, obs_ts: datetime, detail: dict[str, Any]
    ) -> None:
        self._journal(
            session_id,
            None,
            kind,
            source=kind,
            observed_at=iso(obs_ts),
            accepted=False,
            detail=detail,
        )

    # -------------------------------------------------------------- terminate

    def terminate(
        self,
        session_id: str,
        reason: str = "manual_termination",
        observed_at: Optional[str] = None,
    ) -> dict[str, Any]:
        obs_ts = self._coerce_observed(observed_at)
        with self._lock_for(session_id):
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._locked_session(session_id)
                if row["status"] == "terminated":
                    # idempotent: terminal stays terminal, no new watermark
                    self._journal(
                        session_id,
                        None,
                        "terminate",
                        source="admin",
                        observed_at=iso(obs_ts),
                        accepted=False,
                        detail={"rejected": "already terminated", "reason": reason},
                    )
                    self._conn.execute("COMMIT")
                    return self.get_session(session_id)
                seq = row["watermark"] + 1
                gates = [
                    {**g, "open": False, "cleared_by": "termination"}
                    for g in json.loads(row["gates"])
                ]
                state = {
                    "status": "terminated",
                    "revocations": json.loads(row["revocations"]),
                    "gates": gates,
                }
                self._persist_after_event(row, seq, state, last_signal=iso(obs_ts))
                self._journal(
                    session_id,
                    seq,
                    "terminate",
                    source="admin",
                    observed_at=iso(obs_ts),
                    accepted=True,
                    detail={"reason": reason},
                )
                self._conn.execute("COMMIT")
            except StoreError:
                raise
            except sqlite3.Error as exc:
                self._safe_rollback()
                raise StoreError(f"database error: {exc}", 500) from exc
        return self.get_session(session_id)

    # ---------------------------------------------------- per-request decision

    def decide(
        self,
        token: str,
        resource: str,
        action: str,
        country: Optional[str] = None,
        observed_at: Optional[str] = None,
    ) -> Decision:
        """Adjudicate one request against the *current* session watermark and the
        newest policy, clamped by the login-time ceiling.  The verdict and all
        inputs are appended to the immutable audit journal before returning."""
        obs_ts = self._coerce_observed(observed_at)
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE token = ?", (token,)
        ).fetchone()
        if row is None:
            raise StoreError("invalid session token", 401)
        session_id = row["id"]
        with self._lock_for(session_id):
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._locked_session(session_id)
                seq = row["watermark"]
                detail: dict[str, Any] = {}
                reason = "allow"
                allowed = True

                # 1) terminal state is absolute
                if row["status"] == "terminated":
                    allowed, reason = False, "session_terminated"

                # 2) lazy materialisation: an expired attestation is a signal,
                # emitted only once (while no matching open gate already exists)
                if allowed and row["attest_valid_until"]:
                    if obs_ts > parse_iso(row["attest_valid_until"]):
                        already = any(
                            g.get("open")
                            and g["type"] == ATTESTATION
                            and g["signal"] == "device.attestation_expired"
                            for g in json.loads(row["gates"])
                        )
                        if not already:
                            rule = {
                                "id": "attestation-expiry",
                                "signal": "device.attestation_expired",
                                "action": ATTESTATION,
                            }
                            new_state = self._apply_signal(
                                row, "device.attestation_expired", rule, ATTESTATION, {}
                            )
                            seq = row["watermark"] + 1
                            self._persist_after_event(
                                row, seq, new_state, last_signal=iso(obs_ts)
                            )
                            self._journal(
                                session_id,
                                seq,
                                "signal",
                                source="system:clock",
                                observed_at=iso(obs_ts),
                                accepted=True,
                                detail={
                                    "signal": "device.attestation_expired",
                                    "action": ATTESTATION,
                                    "lazy": True,
                                },
                            )
                        allowed, reason = False, "gate:attestation_expired"

                policy = self._get_policy(row["current_policy_v"])
                detail["policy_version"] = row["current_policy_v"]
                detail["initial_policy_version"] = row["initial_policy_v"]

                # 3) open gates (reauth / attestation) block every request.
                # Reload gates because step 2 may have just emitted a lazy event.
                if allowed:
                    fresh_row = self._conn.execute(
                        "SELECT gates, status FROM sessions WHERE id = ?",
                        (session_id,),
                    ).fetchone()
                    if fresh_row["status"] == "terminated":
                        allowed, reason = False, "session_terminated"
                    else:
                        open_gates = [
                            g for g in json.loads(fresh_row["gates"]) if g.get("open")
                        ]
                        if open_gates:
                            allowed = False
                            reason = (
                                f"gate:{open_gates[0]['type']}:"
                                f"{open_gates[0]['signal']}"
                            )
                            detail["open_gates"] = [
                                {
                                    "type": g["type"],
                                    "signal": g["signal"],
                                    "seq": g["seq"],
                                }
                                for g in open_gates
                            ]

                # 4) device proof level must satisfy the *current* policy
                if allowed and row["attest_level"] < policy.device_min_level():
                    allowed, reason = False, "device_level_below_current_policy"
                    detail["required_level"] = policy.device_min_level()
                    detail["attest_level"] = row["attest_level"]

                # 5) network location: a changed country is itself a risk signal
                if allowed and country is not None and country != row["country"]:
                    if policy.country_allowed(country):
                        rule = policy.signal_rule("network.country_changed")
                        if rule:
                            action = rule["action"]
                            new_state = self._apply_signal(
                                row, "network.country_changed", rule, action, {
                                    "from": row["country"], "to": country,
                                }
                            )
                            seq = row["watermark"] + 1
                            self._persist_after_event(
                                row, seq, new_state, country=country,
                                last_signal=iso(obs_ts),
                            )
                            self._journal(
                                session_id,
                                seq,
                                "signal",
                                source="network:geoip",
                                observed_at=iso(obs_ts),
                                accepted=True,
                                detail={
                                    "signal": "network.country_changed",
                                    "action": action,
                                    "from": row["country"],
                                    "to": country,
                                    "lazy": True,
                                },
                            )
                            if action == TERMINATE:
                                allowed, reason = False, "session_terminated"
                            elif action == REVOKE:
                                allowed, reason = False, "revoked:network.country_changed"
                            else:
                                allowed, reason = False, f"gate:{action}:network.country_changed"
                        else:
                            detail["country"] = country
                    else:
                        allowed, reason = False, "country_not_allowed_by_policy"
                        detail["country"] = country

                # 6) current policy evaluation, clamped by the login ceiling
                if allowed:
                    current_grant = policy.evaluate(row["role"], resource, action)
                    ceiling_grant = self._ceiling_allows(
                        json.loads(row["ceiling"]), resource, action
                    )
                    detail["current_policy_grant"] = current_grant
                    detail["ceiling_grant"] = ceiling_grant
                    if not current_grant:
                        allowed, reason = False, "denied_by_current_policy"
                    elif not ceiling_grant:
                        allowed, reason = False, "outside_login_ceiling"

                # 7) grow-only revocation set wins over every grant
                if allowed:
                    hit = self._revocation_hit(
                        json.loads(row["revocations"]), resource, action
                    )
                    if hit:
                        allowed = False
                        reason = f"revoked:{hit['signal']}"
                        detail["revocation"] = hit

                cur = self._conn.execute(
                    "SELECT watermark FROM sessions WHERE id = ?", (session_id,)
                ).fetchone()
                watermark = cur["watermark"]
                detail["watermark"] = watermark
                audit_id = self._record_audit(
                    session_id,
                    watermark,
                    row["current_policy_v"],
                    resource,
                    action,
                    allowed,
                    reason,
                    detail,
                )
                self._conn.execute("COMMIT")
            except StoreError:
                raise
            except sqlite3.Error as exc:
                self._safe_rollback()
                raise StoreError(f"database error: {exc}", 500) from exc
        return Decision(
            allowed=allowed,
            reason=reason,
            policy_version=row["current_policy_v"],
            watermark=watermark,
            audit_id=audit_id,
        )

    @staticmethod
    def _ceiling_allows(ceiling: list[dict[str, Any]], resource: str, action: str) -> bool:

        return any(
            fnmatch.fnmatchcase(resource, pat["resource"])
            and fnmatch.fnmatchcase(action, pat["action"])
            for pat in ceiling
        )

    @staticmethod
    def _revocation_hit(
        revocations: list[dict[str, Any]], resource: str, action: str
    ) -> Optional[dict[str, Any]]:

        for rev in revocations:
            if fnmatch.fnmatchcase(resource, rev["resource"]) and fnmatch.fnmatchcase(
                action, rev["action"]
            ):
                return rev
        return None

    def _record_audit(
        self,
        session_id: str,
        watermark: int,
        policy_version: int,
        resource: str,
        action: str,
        allowed: bool,
        reason: str,
        detail: dict[str, Any],
    ) -> int:
        cur = self._conn.execute(
            """INSERT INTO audit
               (session_id, seq_watermark, policy_version, resource, action,
                allowed, reason, detail, decided_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                session_id,
                watermark,
                policy_version,
                resource,
                action,
                1 if allowed else 0,
                reason,
                json.dumps(detail, sort_keys=True),
                iso(self._clock()),
            ),
        )
        return cur.lastrowid
