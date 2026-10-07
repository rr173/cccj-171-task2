# 零信任访问会话 · 连续风险评估系统

登录成功后，会话与**设备证明、网络位置、用户角色、初始策略版本**四要素绑定；
此后的每个风险信号只能 **收束权限 / 要求再认证 / 终止会话**，永不静默扩大原授权。
策略升级只对新请求生效，已执行操作保留当时裁决。信号乱序、设备证明更新、再认证与
终止并发时，系统形成**单一会话水位**，旧信号不得恢复已撤销权限。

仅依赖 Python 3.10+ 标准库（含 SQLite），无第三方依赖。

## 运行

```bash
python3 -m zta.serve --host 127.0.0.1 --port 8080 --db zta.db
# 浏览器打开 http://127.0.0.1:8080  （会话状态台，2 秒自动刷新）

python3 demo.py            # 十一条安全保证的离线演练
python3 -m unittest discover -s tests -v   # 46 项测试（含并发压测与草稿审批）
```

## 核心机制

### 1. 单一会话水位（single session watermark）

每个会话一把进程内互斥锁 + SQLite `BEGIN IMMEDIATE` 事务，所有事件
（登录 / 信号 / 再认证 / 证明更新 / 终止 / 请求时惰性信号）串行提交，分配会话内
严格单调递增的 `seq`，从 1 开始、连续无空洞无重复。

- **乱序防护**：每个 `source` 记录已接受的最大 `observed_at`；更旧或等时戳的信号
  被拒绝，写入事件日志（`accepted=false, seq=NULL`），**不占水位、不改状态**。
- **nonce 防重放**：再认证与设备证明各自携带单调 nonce，旧 nonce 一律拒绝。
- 每个请求的审计行记录裁决时刻的水位；并发下多个请求拿到明确先后顺序。

### 2. 授权只可收束，三类信号效果

| 信号动作 | 语义 | 可否恢复 |
|---|---|---|
| `revoke` | 条目加入 **grow-only 撤销集**（resource/action 通配） | **永不移除**，再认证/新证明都不行 |
| `reauth` | 打开再认证门，阻断一切请求 | 仅可被更新的再认证事件关闭 |
| `attestation` | 打开设备证明门 | 仅可被更新的设备证明关闭 |
| `terminate` | 终止会话（状态格最大元，终态） | **不可复活**；终止幂等，不重复占水位 |

未知信号**失效关门（fail-closed）**，按再认证门处理。

### 3. 授权天花板（login ceiling）

登录时按初始策略版本把角色 allow 规则具体化为 `(resource, action)` 通配模式快照
（显式 deny 规则预先扣减）。每次请求的裁决为：

```
当前策略允许  ∩  登录天花板允许  −  撤销集  −  开放门控  −  设备/位置约束
```

新策略即使增加了授权，也只能与天花板**取交集**，审计中可见
`current_policy_grant=true` 而 `ceiling_grant=false` → `outside_login_ceiling`。

### 4. 策略版本化，升级不追溯

- 策略为不可变 JSON，`version` 正整数且必须严格递增。
- **新策略只能经「草稿 → 四眼审批」发布**（见第 5 节），接口不再允许直接发布。
- 发布后更新所有存活会话的 `current_policy_v`，**仅对之后的请求生效**。
- 审计是只追加表：每次裁决连同当时的策略版本、水位、原因快照落盘，
  策略升级不会改写历史裁决。

### 5. 草稿审批流程（four-eyes review）

管理员提交的策略**只生成待审草稿**，不触碰生效策略；具备审批权限的操作者核对
差异并提交差异指纹后才发布：

- **权限分离**：操作者身份经 `X-Operator-ID` 头（或 body 内 `operator`）传入。
  内置 `policy-admin`（仅提交）、`policy-approver`（仅审批）、`policy-owner`（两者）。
  未携带身份 → `401 unauthenticated`；权限不足 → `403 forbidden`。
- **差异确认**：提交时快照「基准版本 → 提案」的结构化差异（规则增删改 /
  信号规则 / 约束 / 默认裁决）并计算 SHA256 指纹；审批必须携带
  `diff_digest`，缺失或不符 → `409 diff_mismatch`。
- **幂等确认**：重复审批同一已发布草稿返回同一 `published_version` 且
  `idempotent=true`，不会二次发布；重复拒绝/撤回同样幂等。
- **冲突不覆盖**：审批在 `BEGIN IMMEDIATE` 事务内复核基准版本；若等待期间
  生效版本已变化 → `409 base_version_mismatch`（草稿置 `conflicted`），
  新版本原样保留。并发审批同一草稿只有一次真正发布。
- **拒绝 / 撤回**：仅终结草稿（`rejected` / `withdrawn`），**当前生效策略
  不变**；终态草稿再操作返回 `409 draft_<状态>`。
- **草稿 TTL**：默认 900 秒（提交时可传 `ttl_seconds`）。过期后审批/拒绝/
  撤回一律 `409 draft_expired`，不会发布。
- **天花板依旧**：审批发布的扩权策略只对**新会话**生效；已有会话的登录
  授权上限只能取交集，永不扩张（见第 3 节）。

### 6. 请求时惰性信号

- 设备证明过期：下一次请求时生成 `device.attestation_expired` 门信号（只发一次，
  不重复刷水位）。
- 请求来源国家与会话绑定位置不一致：触发 `network.country_changed` 信号
  （默认策略为全撤销），并更新绑定位置；禁止国家直接拒绝且不改状态。

## HTTP API

所有接口返回 JSON；会话接口用 `Authorization: Bearer <token>`（也支持 body/query
里传 `token`）。策略管理接口用 `X-Operator-ID: <操作者>` 头（也支持 body 里传
`operator`）。

| 方法 & 路径 | 作用 |
|---|---|
| `POST /api/login` | `{user_id, role, country, device_id, attest_level, attest_nonce?}` 建立会话 |
| `POST /api/decide` | `{resource, action, country?}` 逐请求裁决，返回 `allowed/reason/policy_version/watermark/audit_id` |
| `POST /api/signals` | `{signal, source?, observed_at?, detail?}` 风险信号接入 |
| `POST /api/reauth` | `{nonce, clear?}` 再认证（nonce 须递增；可指定清除哪些门） |
| `POST /api/attestation` | `{level, nonce, valid_seconds?}` 更新设备证明 |
| `POST /api/terminate` | `{reason?}` 终止会话（幂等） |
| `POST /api/policies` | **已关闭直接发布**：返回 `403 draft_required` 并提示走草稿流程 |
| `GET /api/policies` | 全部已发布历史版本 |
| `POST /api/policy-drafts` | 提交草稿 `{policy, ttl_seconds?, base_version?}` → 待审草稿（含 diff/digest） |
| `GET /api/policy-drafts?status=` | 草稿列表（默认全部；可筛 `pending`） |
| `GET /api/policy-drafts/<id>` | 单个草稿：差异、指纹、状态、审批结果与事件流水 |
| `POST /api/policy-drafts/<id>/approve` | `{diff_digest}` 确认差异后发布；重复确认幂等；基准变化返回冲突 |
| `POST /api/policy-drafts/<id>/reject` | `{reason?}` 拒绝草稿（生效策略不变） |
| `POST /api/policy-drafts/<id>/withdraw` | `{reason?}` 提交方撤回草稿（生效策略不变） |
| `GET /api/session` | 当前会话状态（天花板/撤销集/门控/水位/证明） |
| `GET /api/events` | 会话事件水位线（含被拒乱序信号） |
| `GET /api/audit?session_id=&limit=` | 逐请求裁决审计（不可变） |
| `GET /api/sessions` | 所有会话 |
| `GET /` | 会话状态台（单页控制台，含草稿/差异/审批面板） |

### 策略 JSON 示例

```json
{
  "version": 2,
  "rules": [
    {"id":"analyst-read", "roles":["analyst"],
     "resources":["dashboard/*","reports/*"], "actions":["read"], "effect":"allow"},
    {"id":"analyst-no-finance", "roles":["analyst"],
     "resources":["finance/*"], "actions":["*"], "effect":"deny"}
  ],
  "constraints": {"device_min_level": 3, "network_countries": ["CN"]},
  "signal_rules": [
    {"id":"kill",  "signal":"security.emergency_kill", "action":"terminate"},
    {"id":"integ", "signal":"device.integrity_failure", "action":"revoke",
     "resources":["*"], "actions":["*"]},
    {"id":"risk",  "signal":"user.risk_score_high", "action":"reauth"},
    {"id":"threat","signal":"device.threat_detected", "action":"attestation"}
  ],
  "default": "deny"
}
```

## 目录

```
zta/
  policy.py   不可变版本化策略模型（角色规则/约束/信号→收束动作）
  store.py    会话状态机 + SQLite：水位锁、天花板、撤销集、门控、审计、
              策略草稿审批（差异指纹/权限/TTL/冲突/幂等）
  api.py      标准库 ThreadingHTTPServer 的 JSON API
  ui.py       会话状态台（内嵌单页，零外部依赖，含草稿差异审批面板）
  serve.py    启动入口
tests/
  test_zta.py   27 项测试：登录绑定/收束语义/乱序/nonce/升级/终态/并发/审计
  test_drafts.py 19 项测试：权限/差异确认/幂等/过期/冲突并发/拒绝撤回/HTTP 面
demo.py         十一条安全保证的可运行演练
```

## 裁决原因码（`reason`）

`allow` · `session_terminated` · `gate:<reauth|attestation>:<signal>` ·
`device_level_below_current_policy` · `country_not_allowed_by_policy` ·
`denied_by_current_policy` · `outside_login_ceiling` ·
`revoked:<signal>` — 每条都逐字进入不可变审计。

### 草稿审批结果码（错误体 `code` 字段）

`unauthenticated`(401) · `forbidden`(403) · `draft_required`(403) ·
`version_too_low`(409) · `base_version_mismatch`(409) ·
`draft_already_pending`(409) · `diff_mismatch`(409) · `draft_expired`(409) ·
`draft_approved` / `draft_rejected` / `draft_withdrawn` / `draft_conflicted`(409)。
成功的重复确认返回 200 且 `idempotent=true`，不产生新版本。
