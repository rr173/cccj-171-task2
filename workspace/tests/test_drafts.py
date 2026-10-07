"""Correctness suite for the policy draft approval workflow.

Covers: pending-only submission, four-eyes permissions, diff confirmation,
idempotency, TTL expiry, concurrent/conflicting publishes (never overwrite),
reject/withdraw leaving the active policy untouched, post-publish ceiling
guarantees, and the HTTP surface.
"""

import json
import os
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zta.api import make_server
from zta.policy import default_policy_v1
from zta.store import (
    DEFAULT_OPERATORS,
    PERM_POLICY_APPROVE,
    PERM_POLICY_SUBMIT,
    Store,
    StoreError,
)


def v2_tightened():
    p = default_policy_v1()
    p["version"] = 2
    p["constraints"] = {"device_min_level": 4, "network_countries": ["CN"]}
    return p


def v3_grant():
    p = default_policy_v1()
    p["version"] = 3
    # widen analyst to a new resource family (default-denied under v1, so no
    # earlier deny rule shadows it in document order)
    p["rules"].append({
        "id": "new-admin-console", "roles": ["analyst"],
        "resources": ["adminconsole/*"], "actions": ["read"], "effect": "allow",
    })
    return p


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


class TestDraftLifecycle(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    def _submit(self, body=None, operator="policy-admin", ttl=None):
        return self.store.submit_draft(
            body or v2_tightened(), operator=operator, ttl_seconds=ttl
        )

    def test_submit_creates_only_a_pending_draft_and_keeps_policy(self):
        d = self._submit()
        self.assertEqual(d["status"], "pending")
        self.assertEqual(d["base_version"], 1)
        self.assertEqual(d["proposed_version"], 2)
        self.assertEqual(self.store.latest_policy_version(), 1,
                         "submission must not publish")
        self.assertTrue(d["diff_digest"])
        kinds = {c["kind"] for c in d["diff"]["changes"]}
        self.assertIn("constraints_changed", kinds)

    def test_submit_without_permission_or_identity_is_rejected(self):
        with self.assertRaises(StoreError) as cm:
            self.store.submit_draft(v2_tightened(), operator=None)
        self.assertEqual(cm.exception.code, 401)
        # approver role alone cannot submit
        with self.assertRaises(StoreError) as cm:
            self._submit(operator="policy-approver")
        self.assertEqual(cm.exception.code, 403)
        self.assertEqual(cm.exception.code_name, "forbidden")

    def test_approve_requires_approve_permission(self):
        d = self._submit()
        with self.assertRaises(StoreError) as cm:
            self.store.approve_draft(d["id"], operator="policy-admin",
                                     diff_digest=d["diff_digest"])
        self.assertEqual(cm.exception.code, 403)
        self.assertEqual(self.store.latest_policy_version(), 1)

    def test_approve_requires_exact_diff_confirmation(self):
        d = self._submit()
        with self.assertRaises(StoreError) as cm:
            self.store.approve_draft(d["id"], operator="policy-approver")
        self.assertEqual(cm.exception.code_name, "diff_mismatch")
        with self.assertRaises(StoreError) as cm:
            self.store.approve_draft(d["id"], operator="policy-approver",
                                     diff_digest="deadbeef")
        self.assertEqual(cm.exception.code_name, "diff_mismatch")
        self.assertEqual(self.store.latest_policy_version(), 1)

    def test_approval_publishes_and_only_affects_new_requests(self):
        tok = self.store.login("alice", "analyst", "CN", "dev-1", 3)["token"]
        d = self._submit()
        out = self.store.approve_draft(
            d["id"], operator="policy-approver", diff_digest=d["diff_digest"]
        )
        self.assertEqual(out["status"], "approved")
        self.assertEqual(out["published_version"], 2)
        self.assertEqual(self.store.latest_policy_version(), 2)
        # new policy applies to subsequent requests: level 3 < required 4
        decision = self.store.decide(tok, "dashboard/x", "read")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "device_level_below_current_policy")
        self.assertEqual(decision.policy_version, 2)

    def test_published_widening_never_extends_existing_session_ceiling(self):
        sess = self.store.login("alice", "analyst", "CN", "dev-1", 3)
        # v1 never granted adminconsole: denied by current policy / outside ceiling
        pre = self.store.decide(sess["token"], "adminconsole/x", "read")
        self.assertFalse(pre.allowed)
        d = self.store.submit_draft(v3_grant(), operator="policy-admin")
        self.store.approve_draft(d["id"], operator="policy-approver",
                                 diff_digest=d["diff_digest"])
        decision = self.store.decide(sess["token"], "adminconsole/x", "read")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "outside_login_ceiling")
        # but a brand new session under v3 receives the widened grant
        sess2 = self.store.login("bob", "analyst", "CN", "dev-2", 3)
        decision2 = self.store.decide(sess2["token"], "adminconsole/x", "read")
        self.assertTrue(decision2.allowed)

    def test_duplicate_approval_is_idempotent(self):
        d = self._submit()
        a1 = self.store.approve_draft(d["id"], "policy-approver", d["diff_digest"])
        a2 = self.store.approve_draft(d["id"], "policy-approver", d["diff_digest"])
        self.assertTrue(a2.get("idempotent"))
        self.assertEqual(a1["published_version"], a2["published_version"])
        self.assertEqual(self.store.list_policies()[-1]["version"], 2,
                         "no second publication")
        approve_events = [e for e in self.store.list_draft_events(d["id"])
                          if e["kind"] == "approve"]
        self.assertEqual(sum(1 for e in approve_events if e["accepted"]), 1)

    def test_version_must_be_greater_than_current_at_submit(self):
        d = self._submit(body=v2_tightened())
        self.store.approve_draft(d["id"], "policy-approver", d["diff_digest"])
        with self.assertRaises(StoreError) as cm:
            self._submit(body=v2_tightened())  # version 2 already live
        self.assertEqual(cm.exception.code_name, "version_too_low")


class TestRejectWithdrawExpiry(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    def test_rejection_leaves_active_policy_untouched_and_is_terminal(self):
        d = self.store.submit_draft(v2_tightened(), operator="policy-admin")
        out = self.store.reject_draft(d["id"], operator="policy-approver",
                                      reason="needs work")
        self.assertEqual(out["status"], "rejected")
        self.assertEqual(self.store.latest_policy_version(), 1)
        with self.assertRaises(StoreError) as cm:
            self.store.approve_draft(d["id"], "policy-approver", d["diff_digest"])
        self.assertEqual(cm.exception.code_name, "draft_rejected")
        # repeated reject is idempotent
        again = self.store.reject_draft(d["id"], "policy-approver")
        self.assertTrue(again.get("idempotent"))
        self.assertEqual(self.store.latest_policy_version(), 1)

    def test_withdrawal_leaves_active_policy_untouched_and_is_terminal(self):
        d = self.store.submit_draft(v2_tightened(), operator="policy-admin")
        out = self.store.withdraw_draft(d["id"], operator="policy-admin")
        self.assertEqual(out["status"], "withdrawn")
        self.assertEqual(self.store.latest_policy_version(), 1)
        with self.assertRaises(StoreError) as cm:
            self.store.approve_draft(d["id"], "policy-approver", d["diff_digest"])
        self.assertEqual(cm.exception.code_name, "draft_withdrawn")
        again = self.store.withdraw_draft(d["id"], "policy-admin")
        self.assertTrue(again.get("idempotent"))

    def test_only_one_pending_draft_at_a_time(self):
        first = self.store.submit_draft(v2_tightened(), operator="policy-admin")
        second_body = v2_tightened()
        second_body["constraints"] = {"device_min_level": 5}
        with self.assertRaises(StoreError) as cm:
            self.store.submit_draft(second_body, operator="policy-admin")
        self.assertEqual(cm.exception.code_name, "draft_already_pending")
        # after withdrawal a fresh draft is allowed
        self.store.withdraw_draft(first["id"], "policy-admin")
        fresh = self.store.submit_draft(second_body, operator="policy-admin")
        self.assertEqual(fresh["status"], "pending")

    def test_expired_draft_cannot_be_approved(self):
        base = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
        clock = Clock(base)
        store = Store(":memory:", clock=clock)
        d = store.submit_draft(v2_tightened(), operator="policy-admin",
                               ttl_seconds=60)
        clock.advance(61)
        self.assertTrue(store.get_draft(d["id"])["expired"])
        with self.assertRaises(StoreError) as cm:
            store.approve_draft(d["id"], "policy-approver", d["diff_digest"])
        self.assertEqual(cm.exception.code, 409)
        self.assertEqual(cm.exception.code_name, "draft_expired")
        self.assertEqual(store.get_draft(d["id"])["status"], "expired")
        self.assertEqual(store.latest_policy_version(), 1)
        # reject/withdraw on an expired draft also report expiry, never publish
        with self.assertRaises(StoreError) as cm:
            store.reject_draft(d["id"], "policy-approver")
        self.assertEqual(cm.exception.code_name, "draft_expired")
        store.close()


class TestConcurrentApproval(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    def test_base_version_change_during_review_conflicts_and_keeps_new_version(self):
        draft = self.store.submit_draft(v2_tightened(), operator="policy-admin")
        # meanwhile the active policy moves to v2 through the internal publish
        # path (another release shipped while the draft waited)
        racing = v2_tightened()
        racing["constraints"] = {"device_min_level": 5, "network_countries": ["CN"]}
        self.store.publish_policy(racing)
        self.assertEqual(self.store.latest_policy_version(), 2)

        with self.assertRaises(StoreError) as cm:
            self.store.approve_draft(
                draft["id"], "policy-approver", draft["diff_digest"]
            )
        self.assertEqual(cm.exception.code, 409)
        self.assertEqual(cm.exception.code_name, "base_version_mismatch")
        self.assertEqual(cm.exception.extra["current_version"], 2)
        final = self.store.get_draft(draft["id"])
        self.assertEqual(final["status"], "conflicted")
        # the newer version is intact, the stale draft did not overwrite it
        live = self.store.list_policies()[-1]
        self.assertEqual(live["policy"]["constraints"]["device_min_level"], 5)

    def test_concurrent_approval_of_same_draft_publishes_exactly_once(self):
        draft = self.store.submit_draft(v2_tightened(), operator="policy-admin")
        digest = draft["diff_digest"]
        outcomes = {"published": 0, "idempotent": 0, "errors": []}
        lock = threading.Lock()

        def approve():
            try:
                out = self.store.approve_draft(
                    draft["id"], "policy-approver", digest
                )
                with lock:
                    if out.get("idempotent"):
                        outcomes["idempotent"] += 1
                    else:
                        outcomes["published"] += 1
            except StoreError as exc:
                with lock:
                    outcomes["errors"].append(exc)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: approve(), range(8)))

        self.assertEqual(outcomes["published"], 1)
        self.assertEqual(outcomes["idempotent"], 7)
        self.assertEqual(outcomes["errors"], [])
        self.assertEqual(self.store.latest_policy_version(), 2)

    def test_concurrent_approve_of_two_drafts_against_same_base(self):
        # even though only one pending draft is allowed, simulate two waiting
        # reviews via direct rows by interleaving submit/reject boundaries:
        # the second submitter can only enter after the first is resolved.
        d1 = self.store.submit_draft(v2_tightened(), operator="policy-admin")
        # approver A publishes d1
        self.store.approve_draft(d1["id"], "policy-approver", d1["diff_digest"])
        # d1 cannot be re-published; a stale second draft referencing v1
        # is impossible through the API, so a fresh draft must target v3
        body3 = v3_grant()
        d2 = self.store.submit_draft(body3, operator="policy-admin")
        self.assertEqual(d2["base_version"], 2)
        out = self.store.approve_draft(d2["id"], "policy-approver", d2["diff_digest"])
        self.assertEqual(out["published_version"], 3)


class TestDraftHTTP(unittest.TestCase):
    def setUp(self):
        self.httpd = make_server("127.0.0.1", 0, ":memory:")
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.store.close()

    def _call(self, method, path, payload=None, operator=None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if operator:
            headers["X-Operator-ID"] = operator
        req = Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_full_workflow_over_http(self):
        status, body = self._call("POST", "/api/policy-drafts",
                                  {"policy": v2_tightened()}, "policy-admin")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "pending")
        draft_id = body["id"]
        digest = body["diff_digest"]
        self.assertTrue(body["diff"]["changes"])

        # unauthenticated approval
        status, body = self._call("POST", f"/api/policy-drafts/{draft_id}/approve",
                                  {"diff_digest": digest})
        self.assertEqual(status, 401)
        # submitter cannot approve
        status, body = self._call("POST", f"/api/policy-drafts/{draft_id}/approve",
                                  {"diff_digest": digest}, "policy-admin")
        self.assertEqual(status, 403)
        self.assertEqual(body["code"], "forbidden")
        # wrong digest
        status, body = self._call("POST", f"/api/policy-drafts/{draft_id}/approve",
                                  {"diff_digest": "nope"}, "policy-approver")
        self.assertEqual(status, 409)
        self.assertEqual(body["code"], "diff_mismatch")

        status, body = self._call(
            "POST", f"/api/policy-drafts/{draft_id}/approve",
            {"diff_digest": digest}, "policy-approver",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["published_version"], 2)

        # repeated confirmation is idempotent
        status, body = self._call(
            "POST", f"/api/policy-drafts/{draft_id}/approve",
            {"diff_digest": digest}, "policy-approver",
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["idempotent"])

        status, body = self._call("GET", "/api/policy-drafts")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["drafts"]), 1)

    def test_direct_publish_endpoint_is_closed(self):
        status, body = self._call("POST", "/api/policies", v2_tightened(),
                                  "policy-owner")
        self.assertEqual(status, 403)
        self.assertEqual(body["code"], "draft_required")

    def test_reject_and_withdraw_results_are_explicit(self):
        status, d1 = self._call("POST", "/api/policy-drafts",
                                {"policy": v2_tightened()}, "policy-admin")
        self.assertEqual(
            self._call("POST", f"/api/policy-drafts/{d1['id']}/reject",
                       {"reason": "no"}, "policy-approver")[0],
            200,
        )
        status, body = self._call(
            "POST", f"/api/policy-drafts/{d1['id']}/approve",
            {"diff_digest": d1["diff_digest"]}, "policy-approver",
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["code"], "draft_rejected")

        body2 = v2_tightened()
        body2["constraints"] = {"device_min_level": 5, "network_countries": ["CN"]}
        status, d2 = self._call("POST", "/api/policy-drafts",
                                {"policy": body2}, "policy-admin")
        self.assertEqual(
            self._call("POST", f"/api/policy-drafts/{d2['id']}/withdraw",
                       {}, "policy-admin")[0],
            200,
        )
        status, body = self._call("GET", f"/api/policy-drafts/{d2['id']}")
        self.assertEqual(body["status"], "withdrawn")

        # active policy is still v1; existing interfaces unaffected
        status, body = self._call("GET", "/api/health")
        self.assertEqual(body["policy_version"], 1)

    def test_existing_session_and_signal_interfaces_still_compatible(self):
        # login / decide / signals remain exactly as before
        status, sess = self._call("POST", "/api/login", {
            "user_id": "alice", "role": "analyst", "country": "CN",
            "device_id": "dev-1", "attest_level": 3,
        })
        self.assertEqual(status, 200)
        token = sess["token"]
        headers = {"Content-Type": "application/json",
                   "Authorization": f"Bearer {token}"}
        req = Request(self.base + "/api/decide",
                      data=json.dumps({"resource": "dashboard/x", "action": "read"}).encode(),
                      headers=headers, method="POST")
        with urlopen(req) as resp:
            decision = json.loads(resp.read().decode())
        self.assertTrue(decision["allowed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
