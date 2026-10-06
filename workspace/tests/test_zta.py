"""Correctness suite for the zero-trust continuous risk engine.

Run:  python -m pytest -q   or   python -m unittest discover -s tests
"""

import os
import sys
import json
import threading
import unittest
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zta.policy import default_policy_v1
from zta.store import SessionTerminated, Store, StoreError


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds")


class Clock:
    def __init__(self, t: datetime):
        self.t = t
        self.lock = threading.Lock()

    def __call__(self) -> datetime:
        with self.lock:
            return self.t

    def advance(self, seconds: float) -> datetime:
        with self.lock:
            self.t = self.t + timedelta(seconds=seconds)
            return self.t


class TestLoginBinding(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    def test_login_snaps_ceiling_and_policy_version(self):
        s = self.store.login("alice", "analyst", "CN", "dev-1", 3)
        self.assertEqual(s["initial_policy_version"], 1)
        self.assertEqual(s["current_policy_version"], 1)
        self.assertEqual(s["watermark"], 1)
        resources = {c["resource"] for c in s["ceiling"]}
        # analyst ceiling contains dashboard/reports reads but NOT finance
        self.assertIn("dashboard/*", resources)
        self.assertIn("reports/*", resources)
        self.assertNotIn("finance/*", resources)

    def test_login_fails_closed_on_low_attestation(self):
        with self.assertRaises(StoreError) as cm:
            self.store.login("bob", "analyst", "CN", "dev-1", 1)
        self.assertEqual(cm.exception.code, 403)

    def test_login_fails_closed_on_disallowed_country(self):
        with self.assertRaises(StoreError):
            self.store.login("bob", "analyst", "RU", "dev-1", 3)

    def test_default_deny_for_ungranted_resource(self):
        s = self.store.login("alice", "analyst", "CN", "dev-1", 3)
        # finance/* carries an explicit deny rule in v1
        d = self.store.decide(s["token"], "finance/secret", "read")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "denied_by_current_policy")
        # a resource no rule mentions is default-denied at both layers
        d2 = self.store.decide(s["token"], "kernel/module", "load")
        self.assertFalse(d2.allowed)
        self.assertEqual(d2.reason, "denied_by_current_policy")

    def test_ceiling_snapshot_blocks_widening(self):
        # analyst ceiling never includes write on dashboard
        s = self.store.login("alice", "analyst", "CN", "dev-1", 3)
        d = self.store.decide(s["token"], "dashboard/x", "write")
        self.assertFalse(d.allowed)
        self.assertIn(d.reason, ("denied_by_current_policy", "outside_login_ceiling"))


class TestSignalConvergence(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.s = self.store.login("alice", "analyst", "CN", "dev-1", 3)
        self.tok = self.s["token"]

    def tearDown(self):
        self.store.close()

    def test_reauth_gate_blocks_then_clears_but_cannot_widen(self):
        d1 = self.store.decide(self.tok, "dashboard/x", "read")
        self.assertTrue(d1.allowed)

        self.store.ingest_signal(self.s["id"], "user.risk_score_high")
        d2 = self.store.decide(self.tok, "dashboard/x", "read")
        self.assertFalse(d2.allowed)
        self.assertTrue(d2.reason.startswith("gate:reauth"))

        self.store.reauthenticate(self.s["id"], nonce=1)
        d3 = self.store.decide(self.tok, "dashboard/x", "read")
        self.assertTrue(d3.allowed)
        # re-auth must not widen beyond the ceiling
        d4 = self.store.decide(self.tok, "finance/secret", "read")
        self.assertFalse(d4.allowed)

    def test_revocation_is_permanent_even_after_reauth_and_attestation(self):
        self.store.ingest_signal(self.s["id"], "device.integrity_failure")
        d = self.store.decide(self.tok, "dashboard/x", "read")
        self.assertFalse(d.allowed)
        self.assertIn("revoked", d.reason)

        self.store.reauthenticate(self.s["id"], nonce=1)
        self.store.update_attestation(self.s["id"], level=5, nonce=2)
        d = self.store.decide(self.tok, "dashboard/x", "read")
        self.assertFalse(d.allowed, "revocation must not be cleared by proof")
        self.assertIn("revoked", d.reason)

    def test_attestation_gate_only_cleared_by_attestation(self):
        self.store.ingest_signal(self.s["id"], "device.threat_detected")
        # re-auth does not clear an attestation gate
        self.store.reauthenticate(self.s["id"], nonce=1)
        d = self.store.decide(self.tok, "dashboard/x", "read")
        self.assertFalse(d.allowed)
        self.assertIn("gate:attestation", d.reason)

        self.store.update_attestation(self.s["id"], level=3, nonce=2)
        d = self.store.decide(self.tok, "dashboard/x", "read")
        self.assertTrue(d.allowed)

    def test_terminate_is_terminal(self):
        self.store.ingest_signal(self.s["id"], "security.emergency_kill")
        with self.assertRaises(SessionTerminated):
            self.store.reauthenticate(self.s["id"], nonce=5)
        with self.assertRaises(SessionTerminated):
            self.store.update_attestation(self.s["id"], level=9, nonce=9)
        d = self.store.decide(self.tok, "dashboard/x", "read")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "session_terminated")
        # a later benign signal can never resurrect it
        with self.assertRaises(SessionTerminated):
            self.store.ingest_signal(self.s["id"], "user.risk_score_low")
        d = self.store.decide(self.tok, "dashboard/x", "read")
        self.assertFalse(d.allowed)

    def test_unknown_signal_fails_closed_as_gate(self):
        self.store.ingest_signal(self.s["id"], "weird.anomaly")
        s = self.store.get_session(self.s["id"])
        self.assertEqual(s["status"], "gated")
        d = self.store.decide(self.tok, "dashboard/x", "read")
        self.assertFalse(d.allowed)


class TestWatermarkOrdering(unittest.TestCase):
    def setUp(self):
        self.base = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)
        self.clock = Clock(self.base)
        self.store = Store(":memory:", clock=self.clock)
        self.s = self.store.login("alice", "analyst", "CN", "dev-1", 3)

    def tearDown(self):
        self.store.close()

    def test_stale_signal_from_same_source_rejected_no_watermark(self):
        w0 = self.s["watermark"]
        self.store.ingest_signal(
            self.s["id"], "user.risk_score_high",
            source="sensor:e", observed_at=iso(self.base + timedelta(seconds=100)),
        )
        # old/out-of-order observation from same source
        self.store.ingest_signal(
            self.s["id"], "device.integrity_failure",
            source="sensor:e", observed_at=iso(self.base + timedelta(seconds=50)),
        )
        s2 = self.store.get_session(self.s["id"])
        events = self.store.list_events(self.s["id"])
        rejected = [e for e in events if not e["accepted"]]
        self.assertTrue(rejected, "stale signal must be journaled as rejected")
        self.assertEqual(rejected[0]["detail"]["rejected"], "stale_out_of_order")
        self.assertIsNone(rejected[0]["seq"])
        # the stale REVOKE signal must NOT have touched the revocation set
        self.assertEqual(
            [r["signal"] for r in s2["revocations"]],
            [],
        )
        self.assertGreaterEqual(s2["watermark"], w0 + 1)

    def test_same_timestamp_is_treated_as_old(self):
        ts = iso(self.base + timedelta(seconds=10))
        self.store.ingest_signal(self.s["id"], "user.risk_score_high",
                                 source="src", observed_at=ts)
        self.store.ingest_signal(self.s["id"], "user.risk_score_high",
                                 source="src", observed_at=ts)
        events = self.store.list_events(self.s["id"])
        self.assertEqual(
            sum(1 for e in events if e["kind"] == "signal" and e["accepted"]), 1
        )

    def test_different_sources_are_ordered_independently(self):
        self.store.ingest_signal(
            self.s["id"], "user.risk_score_high", source="edr",
            observed_at=iso(self.base + timedelta(seconds=100)),
        )
        # older timestamp but a different source: not stale
        s2 = self.store.ingest_signal(
            self.s["id"], "device.threat_detected", source="mdm",
            observed_at=iso(self.base + timedelta(seconds=10)),
        )
        self.assertEqual(len([g for g in s2["gates"] if g["open"]]), 2)

    def test_reauth_nonce_monotonic_blocks_replay(self):
        self.store.ingest_signal(self.s["id"], "user.risk_score_high")
        self.store.reauthenticate(self.s["id"], nonce=7)
        with self.assertRaises(StoreError):
            self.store.reauthenticate(self.s["id"], nonce=7)  # replay
        with self.assertRaises(StoreError):
            self.store.reauthenticate(self.s["id"], nonce=3)  # older

    def test_attestation_nonce_monotonic_blocks_replay(self):
        self.store.update_attestation(self.s["id"], level=4, nonce=2)
        with self.assertRaises(StoreError):
            self.store.update_attestation(self.s["id"], level=4, nonce=2)

    def test_old_signal_after_gate_clear_does_not_reopen(self):
        self.store.ingest_signal(
            self.s["id"], "user.risk_score_high", source="risk",
            observed_at=iso(self.base + timedelta(seconds=10)),
        )
        self.store.reauthenticate(self.s["id"], nonce=1)
        # delayed duplicate of the old signal
        self.store.ingest_signal(
            self.s["id"], "user.risk_score_high", source="risk",
            observed_at=iso(self.base + timedelta(seconds=5)),
        )
        s2 = self.store.get_session(self.s["id"])
        self.assertEqual(s2["status"], "active")
        self.assertFalse(any(g["open"] for g in s2["gates"]))


class TestPolicyUpgrade(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.s = self.store.login("alice", "analyst", "CN", "dev-1", 3)
        self.tok = self.s["token"]

    def tearDown(self):
        self.store.close()

    def _v2_tightened(self):
        p = default_policy_v1()
        p["version"] = 2
        p["constraints"] = {"device_min_level": 4, "network_countries": ["CN"]}
        return p

    def test_upgrade_applies_to_new_requests(self):
        # request under v1 passes at attest level 3
        self.assertTrue(self.store.decide(self.tok, "dashboard/x", "read").allowed)
        self.store.publish_policy(self._v2_tightened())
        d = self.store.decide(self.tok, "dashboard/x", "read")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "device_level_below_current_policy")
        self.assertEqual(d.policy_version, 2)
        # fresh proof satisfies the new policy
        self.store.update_attestation(self.s["id"], level=4, nonce=2)
        self.assertTrue(self.store.decide(self.tok, "dashboard/x", "read").allowed)

    def test_upgrade_never_widens_ceiling(self):
        # v2 tries to grant analyst finance access
        p = default_policy_v1()
        p["version"] = 2
        p["rules"].append(
            {"id": "new-finance", "roles": ["analyst"], "resources": ["finance/*"],
             "actions": ["*"], "effect": "allow"}
        )
        self.store.publish_policy(p)
        d = self.store.decide(self.tok, "finance/secret", "read")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "outside_login_ceiling")

    def test_policy_version_must_be_monotonic_and_immutable(self):
        with self.assertRaises(StoreError):
            self.store.publish_policy(default_policy_v1())  # version 1 exists

    def test_historical_audit_keeps_version_at_time_of_decision(self):
        d1 = self.store.decide(self.tok, "dashboard/x", "read")
        self.store.publish_policy(self._v2_tightened())
        self.store.update_attestation(self.s["id"], level=4, nonce=2)
        d2 = self.store.decide(self.tok, "dashboard/x", "read")
        rows = {r["id"]: r for r in self.store.list_audit(self.s["id"])}
        self.assertEqual(rows[d1.audit_id]["policy_version"], 1)
        self.assertEqual(rows[d2.audit_id]["policy_version"], 2)
        self.assertTrue(rows[d1.audit_id]["allowed"])
        # past verdict is not retroactively rewritten
        self.assertTrue(rows[d1.audit_id]["allowed"])


class TestPolicyDraftApproval(unittest.TestCase):
    def setUp(self):
        self.base = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)
        self.clock = Clock(self.base)
        self.store = Store(":memory:", clock=self.clock, draft_ttl_seconds=60)
        self.session = self.store.login(
            "alice", "analyst", "CN", "dev-1", 3,
        )
        self.admin = {"id": "admin-1", "roles": ["admin"]}
        self.approver = {"id": "approver-1", "roles": ["approver"]}
        self.other_admin = {"id": "admin-2", "roles": ["admin"]}
        self.viewer = {"id": "viewer-1", "roles": ["viewer"]}

    def tearDown(self):
        self.store.close()

    def _draft_policy(self, version=2, **changes):
        p = default_policy_v1()
        p["version"] = version
        p.update(changes)
        return p

    def test_submission_requires_admin_and_does_not_change_active_policy(self):
        with self.assertRaises(StoreError) as cm:
            self.store.submit_policy_draft(self._draft_policy(), self.viewer)
        self.assertEqual(cm.exception.code, 403)
        draft = self.store.submit_policy_draft(self._draft_policy(), self.admin)
        self.assertEqual(draft["status"], "pending")
        self.assertEqual(draft["effective_status"], "pending")
        self.assertEqual(self.store.latest_policy_version(), 1)
        d = self.store.decide(self.session["token"], "dashboard/x", "read")
        self.assertEqual(d.policy_version, 1)

    def test_approver_must_review_diff_and_cannot_self_approve(self):
        submitter_approver = {"id": "same-person", "roles": ["admin", "approver"]}
        draft = self.store.submit_policy_draft(
            self._draft_policy(), submitter_approver
        )
        with self.assertRaises(StoreError) as cm:
            self.store.approve_policy_draft(draft["id"], submitter_approver)
        self.assertEqual(cm.exception.code, 403)

        with self.assertRaises(StoreError) as cm:
            self.store.approve_policy_draft(draft["id"], self.approver)
        self.assertEqual(cm.exception.code, 400)
        self.assertEqual(cm.exception.error_code, "confirm_diff_required")
        self.assertEqual(self.store.latest_policy_version(), 1)

    def test_repeated_approval_is_idempotent(self):
        draft = self.store.submit_policy_draft(
            self._draft_policy(constraints={"device_min_level": 4,
                                            "network_countries": ["CN"]}),
            self.admin,
        )
        first = self.store.approve_policy_draft(
            draft["id"], self.approver, confirm_diff=True, expected_version=2
        )
        second = self.store.approve_policy_draft(
            draft["id"], self.approver, confirm_diff=True, expected_version=2
        )
        self.assertEqual(first["status"], "approved")
        self.assertEqual(second["status"], "approved")
        self.assertEqual(first["published_version"], 2)
        self.assertEqual(second["published_version"], 2)
        self.assertEqual(self.store.latest_policy_version(), 2)
        self.assertEqual(len(self.store.list_policies()), 2)

    def test_reject_and_withdraw_leave_active_policy_unchanged(self):
        rejectable = self.store.submit_policy_draft(self._draft_policy(2), self.admin)
        rejected = self.store.reject_policy_draft(
            rejectable["id"], self.approver, reason="bad diff"
        )
        repeated = self.store.reject_policy_draft(
            rejectable["id"], self.approver, reason="bad diff again"
        )
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(repeated["result_reason"], "bad diff")

        withdrawable = self.store.submit_policy_draft(self._draft_policy(2), self.admin)
        withdrawn = self.store.withdraw_policy_draft(
            withdrawable["id"], self.admin, reason="not ready"
        )
        self.assertEqual(withdrawn["status"], "withdrawn")
        with self.assertRaises(StoreError) as cm:
            self.store.withdraw_policy_draft(withdrawable["id"], self.viewer)
        self.assertEqual(cm.exception.code, 403)
        self.assertEqual(self.store.latest_policy_version(), 1)

    def test_expired_draft_cannot_be_published(self):
        draft = self.store.submit_policy_draft(self._draft_policy(), self.admin)
        self.clock.advance(61)
        with self.assertRaises(StoreError) as cm:
            self.store.approve_policy_draft(draft["id"], self.approver,
                                            confirm_diff=True)
        self.assertEqual(cm.exception.code, 410)
        self.assertEqual(cm.exception.error_code, "draft_expired")
        refreshed = self.store.get_policy_draft(draft["id"])
        self.assertTrue(refreshed["expired"])
        self.assertEqual(refreshed["effective_status"], "expired")
        self.assertEqual(
            [d["id"] for d in self.store.list_policy_drafts(status="expired")],
            [draft["id"]],
        )
        self.assertEqual(self.store.latest_policy_version(), 1)

    def test_approval_conflict_after_base_version_changes_does_not_overwrite(self):
        stale = self.store.submit_policy_draft(self._draft_policy(2), self.admin)

        # A newer policy is published directly by another administrative path.
        newer = self._draft_policy(2)
        newer["default"] = "deny"
        self.store.publish_policy(newer)

        # The stale draft claimed v2 and cannot overwrite the newly published v2.
        with self.assertRaises(StoreError) as cm:
            self.store.approve_policy_draft(stale["id"], self.approver,
                                            confirm_diff=True)
        self.assertEqual(cm.exception.code, 409)
        self.assertEqual(cm.exception.error_code, "policy_version_conflict")
        marked = self.store.get_policy_draft(stale["id"])
        self.assertEqual(marked["status"], "conflicted")
        self.assertEqual(self.store.latest_policy_version(), 2)

    def test_concurrent_approval_publishes_exactly_one_policy(self):
        draft = self.store.submit_policy_draft(self._draft_policy(2), self.admin)
        errors = []

        def approve():
            try:
                self.store.approve_policy_draft(
                    draft["id"], self.approver, confirm_diff=True
                )
            except StoreError as exc:
                errors.append(exc)

        threads = [threading.Thread(target=approve) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(self.store.latest_policy_version(), 2)
        self.assertEqual(len(self.store.list_policies()), 2)


class TestConcurrency(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.s = self.store.login("alice", "analyst", "CN", "dev-1", 3)

    def tearDown(self):
        self.store.close()

    def test_watermark_is_a_single_gapless_sequence_under_load(self):
        n = 40
        base = datetime(2026, 10, 6, tzinfo=timezone.utc)

        def fire(i):
            # every worker is an independent sensor whose observation is newer
            # than the last, so ordering rejection never triggers here
            self.store.ingest_signal(
                self.s["id"], "user.risk_score_high",
                source=f"sensor-{i}",
                observed_at=iso(base + timedelta(milliseconds=i + 1)),
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(fire, range(n)))

        final = self.store.get_session(self.s["id"])
        accepted = [
            e for e in self.store.list_events(self.s["id"])
            if e["seq"] is not None
        ]
        seqs = sorted(e["seq"] for e in accepted)
        # login occupies seq=1, all 40 signals accepted with distinct timestamps
        self.assertEqual(len(seqs), n + 1)
        self.assertEqual(seqs, list(range(1, n + 2)),
                         "watermark must be contiguous, no duplicates/holes")
        self.assertEqual(final["watermark"], n + 1)

    def test_terminate_racing_reauth_and_signals_wins_irreversibly(self):
        outcomes = {"reauth_rejected": 0, "reauth_ok": 0, "signal_rejected": 0}
        lock = threading.Lock()
        sid = self.s["id"]

        def kill():
            self.store.terminate(sid, reason="kill")

        def reauth(i):
            try:
                self.store.reauthenticate(sid, nonce=100 + i)
                with lock:
                    outcomes["reauth_ok"] += 1
            except (SessionTerminated, StoreError):
                with lock:
                    outcomes["reauth_rejected"] += 1

        def signal(i):
            try:
                self.store.ingest_signal(sid, f"sig.{i}", source=f"c{i}")
            except SessionTerminated:
                with lock:
                    outcomes["signal_rejected"] += 1

        with ThreadPoolExecutor(max_workers=10) as pool:
            f_kill = pool.submit(kill)
            futures = [f_kill]
            futures += [pool.submit(reauth, i) for i in range(10)]
            futures += [pool.submit(signal, i) for i in range(10)]
            for f in futures:
                f.result()

        final = self.store.get_session(sid)
        self.assertTrue(final["terminal"])
        # whichever reauth won the race before termination, the session stays dead
        d = self.store.decide(self.s["token"], "dashboard/x", "read")
        self.assertFalse(d.allowed)

    def test_reauth_and_revoke_racing_decision_never_raises_and_fails_safe(self):
        sid = self.s["id"]
        errors = []

        def decide_loop():
            for _ in range(20):
                try:
                    d = self.store.decide(self.s["token"], "dashboard/x", "read")
                    assert d.allowed in (True, False)
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

        def churn():
            for i in range(1, 12):
                try:
                    self.store.ingest_signal(sid, "device.threat_detected",
                                             source="edr-race")
                except SessionTerminated:
                    pass
                try:
                    self.store.update_attestation(sid, level=3, nonce=i + 1)
                except (SessionTerminated, StoreError):
                    pass

        t1 = threading.Thread(target=decide_loop)
        t2 = threading.Thread(target=churn)
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(errors, [])

        # final attestation clears the gate; no revocation was issued by threat gate
        d = self.store.decide(self.s["token"], "dashboard/x", "read")
        self.assertTrue(d.allowed)


class TestAuditAndLazySignals(unittest.TestCase):
    def setUp(self):
        self.base = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)
        self.clock = Clock(self.base)
        self.store = Store(":memory:", clock=self.clock)
        self.s = self.store.login(
            "alice", "analyst", "CN", "dev-1", 3, attest_valid_seconds=60
        )

    def tearDown(self):
        self.store.close()

    def test_every_request_appends_immutable_audit_with_watermark(self):
        self.store.decide(self.s["token"], "dashboard/a", "read")
        self.store.ingest_signal(self.s["id"], "user.risk_score_high")
        self.store.decide(self.s["token"], "dashboard/a", "read")
        rows = self.store.list_audit(self.s["id"])
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[1]["allowed"])
        self.assertFalse(rows[0]["allowed"])  # newest first
        self.assertEqual(rows[0]["reason"], "gate:reauth:user.risk_score_high")

    def test_attestation_expiry_lazy_signal_emitted_once(self):
        self.clock.advance(61)
        d1 = self.store.decide(self.s["token"], "dashboard/a", "read")
        self.assertFalse(d1.allowed)
        self.assertEqual(d1.reason, "gate:attestation_expired")
        w1 = d1.watermark
        d2 = self.store.decide(self.s["token"], "dashboard/a", "read")
        self.assertEqual(d2.watermark, w1, "expiry must not keep raising the watermark")

    def test_country_change_emits_revoke_and_denies(self):
        d = self.store.decide(self.s["token"], "dashboard/a", "read", country="US")
        self.assertFalse(d.allowed)
        self.assertIn("revoked", d.reason)
        s = self.store.get_session(self.s["id"])
        self.assertEqual(s["country"], "US")
        self.assertTrue(s["revocations"])
        # moving back does not restore privileges
        d2 = self.store.decide(self.s["token"], "dashboard/a", "read", country="CN")
        self.assertFalse(d2.allowed)

    def test_disallowed_country_denied_without_state_change(self):
        w0 = self.store.get_session(self.s["id"])["watermark"]
        d = self.store.decide(self.s["token"], "dashboard/a", "read", country="RU")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "country_not_allowed_by_policy")
        self.assertEqual(self.store.get_session(self.s["id"])["watermark"], w0)


class TestDraftHttpApi(unittest.TestCase):
    def setUp(self):
        from zta.api import make_server
        self.httpd = make_server("127.0.0.1", 0, ":memory:")
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_port

    def tearDown(self):
        self.httpd.shutdown()
        self.thread.join()
        self.httpd.server_close()
        self.httpd.store.close()

    def request(self, method, path, body=None, headers=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        payload = json.dumps(body).encode() if body is not None else None
        h = headers or {}
        if payload is not None:
            h = {**h, "Content-Type": "application/json"}
        conn.request(method, path, body=payload, headers=h)
        response = conn.getresponse()
        data = json.loads(response.read().decode())
        conn.close()
        return response.status, data

    def test_draft_approval_http_results_and_unauthorized_access(self):
        p = default_policy_v1()
        p["version"] = 2
        status, body = self.request("POST", "/api/policies", p)
        self.assertEqual(status, 401)
        self.assertEqual(body["code"], "unauthorized")

        status, body = self.request(
            "POST", "/api/policies", p,
            {"X-User-Id": "admin-1", "X-User-Roles": "admin"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["submitted"])
        draft_id = body["draft"]["id"]

        status, body = self.request(
            "POST", f"/api/policy-drafts/{draft_id}/approve",
            {"confirm_diff": True},
            {"X-User-Id": "approver-1", "X-User-Roles": "viewer"},
        )
        self.assertEqual(status, 403)

        status, first = self.request(
            "POST", f"/api/policy-drafts/{draft_id}/approve",
            {"confirm_diff": True, "expected_version": 2},
            {"X-User-Id": "approver-1", "X-User-Roles": "approver"},
        )
        self.assertEqual(status, 200)
        self.assertFalse(first["idempotent"])
        status, second = self.request(
            "POST", f"/api/policy-drafts/{draft_id}/approve",
            {"confirm_diff": True, "expected_version": 2},
            {"X-User-Id": "approver-1", "X-User-Roles": "approver"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(second["idempotent"])
        self.assertEqual(self.httpd.store.latest_policy_version(), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
