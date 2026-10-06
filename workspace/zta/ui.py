"""Session state console (single-page, no external dependencies)."""

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>零信任会话 · 连续风险评估</title>
<style>
  :root { --bg:#0f1420; --panel:#171e2e; --line:#26304a; --fg:#dce4f5;
          --muted:#8492b3; --ok:#3ddc84; --bad:#ff5c79; --warn:#ffb347;
          --accent:#5b8cff; }
  * { box-sizing: border-box; }
  body { margin:0; font:14px/1.5 -apple-system,Segoe UI,Roboto,"PingFang SC",sans-serif;
         background:var(--bg); color:var(--fg); }
  header { padding:14px 22px; border-bottom:1px solid var(--line);
           display:flex; align-items:center; gap:14px; }
  header h1 { font-size:16px; margin:0; }
  header .muted { color:var(--muted); font-size:12px; }
  main { display:grid; grid-template-columns: 420px 1fr; gap:16px; padding:16px 22px; }
  @media (max-width: 980px){ main{ grid-template-columns:1fr; } }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:10px;
          padding:14px 16px; margin-bottom:14px; }
  .card h2 { font-size:13px; margin:0 0 10px; color:var(--muted);
             text-transform:uppercase; letter-spacing:.06em; }
  label { display:block; font-size:12px; color:var(--muted); margin:8px 0 3px; }
  input, select, textarea { width:100%; background:#0e1424; color:var(--fg);
          border:1px solid var(--line); border-radius:6px; padding:7px 9px; font-size:13px; }
  textarea { font-family:ui-monospace,Menlo,Consolas,monospace; min-height:110px; }
  button { background:var(--accent); color:#fff; border:0; border-radius:6px;
           padding:8px 14px; font-size:13px; cursor:pointer; margin:8px 6px 0 0; }
  button.ghost { background:#24304d; }
  button.danger { background:var(--bad); }
  button:disabled { opacity:.45; cursor:not-allowed; }
  .row { display:flex; gap:8px; }
  .row > * { flex:1; }
  .pill { display:inline-block; padding:2px 9px; border-radius:99px; font-size:12px;
          font-weight:600; }
  .pill.active { background:rgba(61,220,132,.15); color:var(--ok); }
  .pill.gated { background:rgba(255,179,71,.15); color:var(--warn); }
  .pill.terminated { background:rgba(255,92,121,.18); color:var(--bad); }
  .kv { display:grid; grid-template-columns:130px 1fr; gap:4px 10px; font-size:13px; }
  .kv dt { color:var(--muted); } .kv dd { margin:0; word-break:break-all; }
  table { width:100%; border-collapse:collapse; font-size:12.5px; }
  th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line);
          vertical-align:top; }
  th { color:var(--muted); font-weight:600; }
  .allow { color:var(--ok); font-weight:700; }
  .deny { color:var(--bad); font-weight:700; }
  .tag { font-family:ui-monospace,Menlo,monospace; font-size:11.5px; }
  details summary { cursor:pointer; color:var(--muted); font-size:12px; }
  pre { background:#0e1424; border:1px solid var(--line); border-radius:6px;
        padding:8px; overflow:auto; font-size:11.5px; margin:6px 0 0;
        max-height:240px; }
  #toast { position:fixed; right:18px; bottom:18px; max-width:420px; }
  .toast-item { background:#1d2740; border:1px solid var(--line); border-radius:8px;
        padding:10px 14px; margin-top:8px; font-size:13px; }
  .toast-item.err { border-color:var(--bad); }
  .toast-item.ok { border-color:var(--ok); }
  .muted { color:var(--muted); }
  .seq { color:var(--accent); font-weight:700; }
  .stale { color:var(--warn); }
</style>
</head>
<body>
<header>
  <h1>🛡 零信任访问会话 — 连续风险评估台</h1>
  <span class="muted">信号只能收束权限 / 要求再认证 / 终止会话 · 单会话水位 · 策略版本化</span>
</header>

<main>
  <section>
    <div class="card" id="loginCard">
      <h2>1 · 登录建立会话（绑定设备/位置/角色/策略版本）</h2>
      <div class="row">
        <div><label>用户</label><input id="li_user" value="alice"></div>
        <div><label>角色</label>
          <select id="li_role"><option>analyst</option><option>admin</option></select>
        </div>
      </div>
      <div class="row">
        <div><label>网络位置 (国家)</label>
          <select id="li_country"><option>CN</option><option>US</option><option value="">(无)</option><option>RU</option></select>
        </div>
        <div><label>设备 ID</label><input id="li_device" value="dev-book-01"></div>
      </div>
      <div class="row">
        <div><label>设备证明等级</label><input id="li_level" type="number" value="3"></div>
        <div><label>证明 nonce</label><input id="li_nonce" type="number" value="1"></div>
      </div>
      <button onclick="login()">登录 / 创建会话</button>
    </div>

    <div class="card">
      <h2>2 · 风险信号（仅可收束）</h2>
      <label>信号</label>
      <select id="sig_name">
        <option value="user.risk_score_high">user.risk_score_high → 再认证门</option>
        <option value="device.threat_detected">device.threat_detected → 设备证明门</option>
        <option value="device.integrity_failure">device.integrity_failure → 撤销全部</option>
        <option value="network.country_changed">network.country_changed → 撤销全部</option>
        <option value="security.emergency_kill">security.emergency_kill → 终止</option>
        <option value="custom.unknown">custom.unknown → 未知信号(失效关门=再认证)</option>
      </select>
      <div class="row">
        <div><label>source（乱序测试用）</label><input id="sig_source" value="sensor:edr"></div>
        <div><label>observed_at（留空=现在；可填过去时间制造乱序）</label>
          <input id="sig_obs" placeholder="2026-10-06T01:00:00+00:00"></div>
      </div>
      <button onclick="sendSignal()">提交信号</button>
      <button class="ghost" onclick="staleBurst()">并发：先新后旧（旧信号不得回滚）</button>
    </div>

    <div class="card">
      <h2>3 · 再认证 / 设备证明更新 / 终止</h2>
      <div class="row">
        <div><label>再认证 nonce（须递增）</label><input id="re_nonce" type="number" value="1"></div>
        <div style="display:flex;align-items:flex-end">
          <button onclick="reauth()">再认证（清再认证门）</button>
        </div>
      </div>
      <div class="row">
        <div><label>新证明等级</label><input id="at_level" type="number" value="3"></div>
        <div><label>新证明 nonce（须递增）</label><input id="at_nonce" type="number" value="2"></div>
        <div style="display:flex;align-items:flex-end">
          <button onclick="attest()">更新设备证明（清证明门）</button>
        </div>
      </div>
      <button class="danger" onclick="terminate()">终止会话</button>
      <button class="ghost" onclick="concurrentKill()">并发：终止 × 再认证（终态不可复活）</button>
    </div>

    <div class="card">
      <h2>4 · 策略 API（新版本对新请求生效）</h2>
      <details open><summary>策略 JSON（version 必须大于当前）</summary>
        <textarea id="policyJson"></textarea></details>
      <button onclick="publishPolicy()">发布新版本</button>
      <button class="ghost" onclick="loadTightenedPolicy()">载入「收紧」模板(v2)</button>
    </div>

    <div class="card">
      <h2>5 · 逐请求裁决（审计）</h2>
      <div class="row">
        <div><label>资源</label><input id="q_resource" value="dashboard/finance-q3"></div>
        <div><label>动作</label>
          <select id="q_action"><option>read</option><option>write</option><option>delete</option></select></div>
        <div><label>本次来源国家</label>
          <select id="q_country"><option value="">(同会话)</option><option>CN</option><option>US</option><option>RU</option></select></div>
      </div>
      <button onclick="decide()">发起请求裁决</button>
      <label>&nbsp;</label>
      <div id="lastDecision" class="muted">尚未裁决</div>
    </div>
  </section>

  <section>
    <div class="card">
      <h2>会话状态（水位单一真相）</h2>
      <div id="sessionView" class="muted">未登录。登录后此处显示实时状态，每 2 秒自动刷新。</div>
    </div>
    <div class="card">
      <h2>事件水位线（accepted=0 的旧信号不占 seq）</h2>
      <div style="max-height:280px;overflow:auto"><table id="eventTable">
        <thead><tr><th>seq</th><th>事件</th><th>来源</th><th>observed_at</th><th>结果</th></tr></thead>
        <tbody></tbody></table></div>
    </div>
    <div class="card">
      <h2>逐请求裁决审计（不可变）</h2>
      <div style="max-height:360px;overflow:auto"><table id="auditTable">
        <thead><tr><th>#</th><th>时间</th><th>水位</th><th>策略v</th><th>资源</th><th>动作</th><th>裁决</th><th>原因</th></tr></thead>
        <tbody></tbody></table></div>
    </div>
  </section>
</main>
<div id="toast"></div>

<script>
let TOKEN = localStorage.getItem('zta_token') || null;
let timer = null;

function toast(msg, kind='') {
  const box = document.getElementById('toast');
  const el = document.createElement('div');
  el.className = 'toast-item ' + kind;
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

async function api(path, body) {
  const opts = body !== undefined
    ? { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) }
    : {};
  if (TOKEN && path !== '/api/login') {
    opts.headers = opts.headers || {};
    opts.headers['Authorization'] = 'Bearer ' + TOKEN;
  }
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}

async function login() {
  const body = {
    user_id: val('li_user'), role: val('li_role'),
    country: val('li_country') || null, device_id: val('li_device'),
    attest_level: +val('li_level'), attest_nonce: +val('li_nonce'),
  };
  try {
    const s = await api('/api/login', body);
    TOKEN = s.token; localStorage.setItem('zta_token', TOKEN);
    toast('会话已建立 ' + s.id, 'ok');
    refresh(); startPolling();
  } catch (e) { toast('登录被拒：' + e.message, 'err'); }
}

async function sendSignal() {
  try {
    const s = await api('/api/signals', {
      signal: val('sig_name'), source: val('sig_source') || undefined,
      observed_at: val('sig_obs') || undefined,
    });
    toast('信号已并入水位 seq=' + s.watermark + ' → ' + s.status, 'ok');
    refresh();
  } catch (e) { toast(e.message, 'err'); }
}

async function staleBurst() {
  // Fire a fresh signal and an older one "concurrently"; the older must be rejected.
  const oldTs = '2020-01-01T00:00:00+00:00';
  const results = await Promise.allSettled([
    api('/api/signals', { signal:'user.risk_score_high', source:'sensor:x' }),
    api('/api/signals', { signal:'user.risk_score_high', source:'sensor:x', observed_at: oldTs }),
  ]);
  toast('并发结果：新信号 ' + (results[0].status==='fulfilled'?'已接受':'失败')
        + '；旧信号 ' + (results[1].status==='rejected'?'已拒绝并记录':'异常!'),
        results[1].status==='rejected' ? 'ok' : 'err');
  refresh();
}

async function reauth() {
  try { const s = await api('/api/reauth', { nonce: +val('re_nonce') });
    toast('再认证完成，水位 seq=' + s.watermark, 'ok'); refresh();
  } catch (e) { toast(e.message, 'err'); }
}
async function attest() {
  try { const s = await api('/api/attest', { level: +val('at_level'), nonce: +val('at_nonce') });
    toast('设备证明已更新，水位 seq=' + s.watermark, 'ok'); refresh();
  } catch (e) { toast(e.message, 'err'); }
}
async function terminate() {
  try { const s = await api('/api/terminate', { reason:'console' });
    toast('会话已终止（终态）', 'ok'); refresh();
  } catch (e) { toast(e.message, 'err'); }
}
async function concurrentKill() {
  const r = await Promise.allSettled([
    api('/api/terminate', { reason:'kill-switch' }),
    new Promise(res => setTimeout(() => res(api('/api/reauth', { nonce: 999 })), 20)),
  ]);
  toast('终止=' + (r[0].status==='fulfilled'?'成功':'失败')
      + '，并发再认证=' + (r[1].status==='fulfilled'?'成功(异常!)':'被终态拒绝'),
      r[1].status==='rejected'?'ok':'err');
  refresh();
}

async function publishPolicy() {
  let body;
  try { body = JSON.parse(val('policyJson')); }
  catch(e){ return toast('JSON 解析失败：'+e.message,'err'); }
  try { await api('/api/policies', body);
    toast('策略 v'+body.version+' 已发布（对新请求生效）','ok');
  } catch(e){ toast(e.message,'err'); }
}
async function loadTightenedPolicy() {
  const cur = await api('/api/policies');
  const nextV = Math.max(...cur.policies.map(p=>p.version)) + 1;
  const p = structuredClone(cur.policies.at(-1).policy);
  p.version = nextV;
  // tighten: analyst loses dashboard writes-adjacent wildcard? shrink countries & raise level
  p.constraints = { device_min_level: 4, network_countries: ['CN'] };
  val('policyJson', JSON.stringify(p, null, 2));
}

async function decide() {
  try {
    const d = await api('/api/decide', {
      resource: val('q_resource'), action: val('q_action'),
      country: val('q_country') || null,
    });
    document.getElementById('lastDecision').innerHTML =
      (d.allowed?'<span class="allow">ALLOW</span>':'<span class="deny">DENY</span>')
      + ' · reason=<span class="tag">'+d.reason+'</span>'
      + ' · 水位 '+d.watermark + ' · 策略 v'+d.policy_version
      + ' · 审计 #'+d.audit_id;
    refresh();
  } catch(e){ toast(e.message,'err'); }
}

function val(id, v) {
  const el = document.getElementById(id);
  if (v === undefined) return el.value;
  el.value = v;
}

function esc(s){ return String(s??'').replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function renderSession(s) {
  if (!s) { document.getElementById('sessionView').innerHTML =
      '<span class="muted">无有效会话（令牌可能已失效）。</span>'; return; }
  document.getElementById('sessionView').innerHTML = `
    <dl class="kv">
      <dt>会话</dt><dd class="tag">${esc(s.id)}</dd>
      <dt>用户 / 角色</dt><dd>${esc(s.user_id)} / <b>${esc(s.role)}</b></dd>
      <dt>状态</dt><dd><span class="pill ${s.status}">${esc(s.status)}</span>
        ${s.terminal?'（终态不可复活）':''}</dd>
      <dt>水位 seq</dt><dd class="seq">${s.watermark}</dd>
      <dt>初始策略版本</dt><dd>v${s.initial_policy_version}（授权天花板在此固化）</dd>
      <dt>当前策略版本</dt><dd>v${s.current_policy_version}（仅对新请求生效）</dd>
      <dt>网络位置</dt><dd>${esc(s.country||'—')}</dd>
      <dt>设备</dt><dd>${esc(s.device_id)} · 证明等级 ${s.attestation.level}
        · nonce ${s.attestation.nonce}<br>
        <span class="muted">签发 ${esc(s.attestation.issued_at)}<br>有效至 ${esc(s.attestation.valid_until||'不限')}</span></dd>
      <dt>再认证 nonce</dt><dd>${s.reauth_nonce}</dd>
      <dt>授权天花板</dt><dd>${s.ceiling.length} 条 (resource,action) 模式，永不扩大</dd>
    </dl>
    <details ${s.revocations.length?'open':''}><summary>撤销集（grow-only，只增不移除）× ${s.revocations.length}</summary>
      <pre>${esc(JSON.stringify(s.revocations,null,2))}</pre></details>
    <details ${s.gates.some(g=>g.open)?'open':''}><summary>门控（再认证/证明可关闭，撤销不可）</summary>
      <pre>${esc(JSON.stringify(s.gates,null,2))}</pre></details>`;
}

function renderEvents(evs) {
  const tb = document.querySelector('#eventTable tbody');
  tb.innerHTML = evs.slice().reverse().map(e => `
    <tr class="${e.accepted?'':'stale'}">
      <td>${e.seq===null?'<span class="stale">—</span>':'<span class="seq">'+e.seq+'</span>'}</td>
      <td><span class="tag">${esc(e.kind)}</span><br>
        <span class="muted">${esc(e.detail.signal||e.detail.reason||e.detail.cleared_gates||'')}</span>
        ${e.detail.action?' · '+esc(e.detail.action):''}</td>
      <td class="tag">${esc(e.source||'')}</td>
      <td class="muted">${esc(e.observed_at||'')}</td>
      <td>${e.accepted?'<span class="allow">accepted</span>':'<span class="deny">rejected: '+esc(e.detail.rejected||'')+'</span>'}</td>
    </tr>`).join('');
}

function renderAudit(rows) {
  const tb = document.querySelector('#auditTable tbody');
  tb.innerHTML = rows.map(a => `
    <tr>
      <td>${a.id}</td><td class="muted">${esc(a.decided_at)}</td>
      <td class="seq">${a.seq_watermark}</td><td>v${a.policy_version}</td>
      <td class="tag">${esc(a.resource)}</td><td class="tag">${esc(a.action)}</td>
      <td>${a.allowed?'<span class="allow">ALLOW</span>':'<span class="deny">DENY</span>'}</td>
      <td class="tag">${esc(a.reason)}</td>
    </tr>`).join('');
}

async function refresh() {
  if (!TOKEN) return;
  try {
    const [s, evs, audit] = await Promise.all([
      api('/api/session'), api('/api/events'), api('/api/audit?limit=50'),
    ]);
    renderSession(s); renderEvents(evs.events); renderAudit(audit.audit);
  } catch (e) {
    if (/token|terminated/i.test(e.message)) {
      TOKEN = null; localStorage.removeItem('zta_token');
    }
  }
}
function startPolling() {
  clearInterval(timer);
  timer = setInterval(refresh, 2000);
}

if (TOKEN) { refresh(); startPolling(); }
api('/api/policies').then(p => {
  if (!val('policyJson')) val('policyJson', JSON.stringify(
    { ...p.policies.at(-1).policy, version: p.policies.at(-1).version+1 }, null, 2));
});
</script>
</body>
</html>
"""
