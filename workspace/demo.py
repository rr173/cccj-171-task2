#!/usr/bin/env python3
"""Self-contained walk-through of every security guarantee.

    python3 demo.py
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone

from zta.policy import default_policy_v1
from zta.store import SessionTerminated, Store, StoreError


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds")


def heading(t: str) -> None:
    print("\n" + "=" * 72 + f"\n{t}\n" + "-" * 72)


def verdict(d) -> str:
    word = "ALLOW" if d.allowed else "DENY "
    return f"{word} reason={d.reason:<38} watermark={d.watermark} policy=v{d.policy_version}"


def main() -> None:
    base = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
    clock_t = {"t": base}
    store = Store(":memory:", clock=lambda: clock_t["t"])

    heading("1. 登录：绑定设备证明 / 网络位置 / 角色 / 初始策略版本，固化授权天花板")
    s = store.login("alice", "analyst", "CN", "dev-book-01", attest_level=3)
    print(f"session={s['id']}  initial_policy=v{s['initial_policy_version']}  "
          f"ceiling={len(s['ceiling'])} patterns (dashboard/reports read only)")

    heading("2. 正常请求被允许，逐请求写入不可变审计")
    print(verdict(store.decide(s["token"], "dashboard/q3", "read")))
    print(verdict(store.decide(s["token"], "finance/payroll", "read")),
          " <- 初始策略从未授予")

    heading("3. 风险信号只能收束：高风险 -> 再认证门")
    store.ingest_signal(s["id"], "user.risk_score_high", source="edr",
                        observed_at=iso(base + timedelta(seconds=30)))
    print(verdict(store.decide(s["token"], "dashboard/q3", "read")))

    heading("4. 乱序旧信号：更早的时间戳被拒绝并留痕，不占水位、不改状态")
    before = store.get_session(s["id"])
    store.ingest_signal(s["id"], "device.integrity_failure", source="edr",
                        observed_at=iso(base + timedelta(seconds=10)))
    after = store.get_session(s["id"])
    print(f"watermark {before['watermark']} -> {after['watermark']} (不变); "
          f"revocations={after['revocations']} (空)")
    ev = [e for e in store.list_events(s["id"]) if not e["accepted"]][0]
    print(f"rejected event: seq={ev['seq']} reason={ev['detail']['rejected']}")

    heading("5. 再认证只清自己的门，且 nonce 必须递增（防重放）")
    store.reauthenticate(s["id"], nonce=1)
    print(verdict(store.decide(s["token"], "dashboard/q3", "read")))
    try:
        store.reauthenticate(s["id"], nonce=1)
    except StoreError as e:
        print(f"replay nonce rejected: {e}")

    heading("6. 撤销只增不移除：设备完整性失败后，再认证/新证明都无法恢复")
    store.ingest_signal(s["id"], "device.integrity_failure", source="mdm",
                        observed_at=iso(base + timedelta(seconds=60)))
    store.reauthenticate(s["id"], nonce=2)
    store.update_attestation(s["id"], level=5, nonce=2,
                             observed_at=iso(base + timedelta(seconds=70)))
    print(verdict(store.decide(s["token"], "dashboard/q3", "read")))

    heading("7. 策略升级对新请求生效，但天花板永不扩大")
    v2 = default_policy_v1()
    v2["version"] = 2
    v2["rules"].append({"id": "new-grant", "roles": ["analyst"],
                        "resources": ["finance/*"], "actions": ["*"], "effect": "allow"})
    store.publish_policy(v2)
    d = store.decide(s["token"], "finance/payroll", "read")
    print(verdict(d), " <- 当前策略放行，但天花板拦截（不静默扩权）")

    heading("8. 已执行操作保留当时裁决（审计快照不被追溯改写）")
    for row in store.list_audit(s["id"]):
        print(f"audit#{row['id']:<2} wm={row['seq_watermark']} "
              f"policy=v{row['policy_version']} "
              f"{'ALLOW' if row['allowed'] else 'DENY '} "
              f"{row['action']:<6} {row['resource']:<18} {row['reason']}")

    heading("9. 终止是最大状态：再认证/证明/信号并发都不能复活")
    store2 = Store(":memory:")
    s2 = store2.login("bob", "analyst", "US", "dev-9", 4)

    def race():
        errors = []
        def kill():
            store2.terminate(s2["id"], reason="emergency")
        def reauth(i):
            try: store2.reauthenticate(s2["id"], nonce=100 + i)
            except (SessionTerminated, StoreError) as e: errors.append(("reauth", e))
        def attest(i):
            try: store2.update_attestation(s2["id"], 5, nonce=200 + i)
            except (SessionTerminated, StoreError) as e: errors.append(("attest", e))
        def signal(i):
            try: store2.ingest_signal(s2["id"], f"x.sig{i}", source=f"race{i}")
            except SessionTerminated as e: errors.append(("signal", e))
        threads = [threading.Thread(target=kill)]
        threads += [threading.Thread(target=reauth, args=(i,)) for i in range(5)]
        threads += [threading.Thread(target=attest, args=(i,)) for i in range(5)]
        threads += [threading.Thread(target=signal, args=(i,)) for i in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        return errors

    errs = race()
    final = store2.decide(s2["token"], "dashboard/x", "read")
    print(f"{len(errs)} post-termination ops correctly rejected; "
          f"final={verdict(final)}")

    heading("10. 40 路乱序信号压测：水位连续无空洞、无重复")
    store3 = Store(":memory:")
    s3 = store3.login("carol", "admin", "CN", "dev-3", 5)
    sem = threading.BoundedSemaphore(8)
    def fire(i):
        # each of the 40 concurrent emitters is an independent sensor, with a
        # newer observation; the engine must still serialise them into one
        # gapless watermark
        store3.ingest_signal(
            s3["id"], "user.risk_score_high", source=f"sensor-{i}",
            observed_at=iso(base + timedelta(milliseconds=i + 1)),
        )
    def guarded(i):
        with sem:
            fire(i)
    threads = [threading.Thread(target=guarded, args=(i,)) for i in range(40)]
    for t in threads: t.start()
    for t in threads: t.join()
    seqs = sorted(e["seq"] for e in store3.list_events(s3["id"]) if e["seq"] is not None)
    print(f"accepted seq = {seqs[0]}..{seqs[-1]}, contiguous={seqs == list(range(1, len(seqs)+1))}")
    store.close(); store2.close(); store3.close()

    heading("11. 策略草稿审批：四眼确认差异后发布；拒绝/撤回/过期/冲突不改生效策略")
    clock_t = {"t": base}
    store4 = Store(":memory:", clock=lambda: clock_t["t"])
    sess = store4.login("dave", "analyst", "CN", "dev-11", 3)
    tightened = default_policy_v1()
    tightened["version"] = 2
    tightened["constraints"] = {"device_min_level": 4, "network_countries": ["CN"]}

    draft = store4.submit_draft(tightened, operator="policy-admin", ttl_seconds=60)
    print(f"草稿 {draft['id']}: pending, 基线 v{draft['base_version']} "
          f"-> 提案 v{draft['proposed_version']}, 生效版本仍为 "
          f"v{store4.latest_policy_version()}")
    print("差异:", [(c["kind"], c.get("from"), c.get("to"))
                    for c in draft["diff"]["changes"]])
    try:
        store4.approve_draft(draft["id"], operator="policy-admin",
                             diff_digest=draft["diff_digest"])
    except StoreError as e:
        print(f"提交人无权审批 -> {e.code} {e.code_name}")
    try:
        store4.approve_draft(draft["id"], operator="policy-approver",
                             diff_digest="wrong")
    except StoreError as e:
        print(f"差异指纹不符 -> {e.code} {e.code_name}")
    approved = store4.approve_draft(draft["id"], operator="policy-approver",
                                    diff_digest=draft["diff_digest"])
    print(f"审批通过 -> published v{approved['published_version']}；"
          f"重复确认幂等={store4.approve_draft(draft['id'], 'policy-approver', draft['diff_digest']).get('idempotent')}")
    print("发布后新请求:", verdict(store4.decide(sess['token'], "dashboard/q3", "read")),
          "（旧会话的授权上限不扩张，只按新策略收束）")

    # reject leaves the live policy untouched
    v3 = default_policy_v1(); v3["version"] = 3
    rejected = store4.submit_draft(v3, operator="policy-admin")
    store4.reject_draft(rejected["id"], operator="policy-approver", reason="nope")
    print(f"拒绝后生效版本仍为 v{store4.latest_policy_version()}")

    # expiry + concurrent base change => conflict, never overwrite
    short = default_policy_v1(); short["version"] = 3
    expired = store4.submit_draft(short, operator="policy-admin", ttl_seconds=60)
    clock_t["t"] = clock_t["t"] + timedelta(seconds=61)
    try:
        store4.approve_draft(expired["id"], "policy-approver", expired["diff_digest"])
    except StoreError as e:
        print(f"过期草稿审批 -> {e.code} {e.code_name}")
    store4.close()


if __name__ == "__main__":
    main()
