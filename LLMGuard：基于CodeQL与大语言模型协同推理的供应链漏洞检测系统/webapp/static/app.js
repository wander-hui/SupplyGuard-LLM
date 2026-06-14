// SupplyGuard-LLM Web UI 前端逻辑
const $ = (id) => document.getElementById(id);
let PROVIDERS = {};
let pollTimer = null;

// ---------------- 标签切换 ----------------
document.querySelectorAll('.tab').forEach(t => {
  t.onclick = () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    $('panel-' + t.dataset.tab).classList.add('active');
  };
});

// ---------------- 初始化: 拉取厂商信息 ----------------
async function init() {
  const r = await fetch('/api/providers');
  const d = await r.json();
  PROVIDERS = d.providers;
  $('kbBadge').textContent = `知识库 ${d.kb.entries} 条危险组件`;
  updateProviderHint();
  loadCfg();
}

function updateProviderHint() {
  const p = PROVIDERS[$('provider').value];
  if (!p) return;
  $('providerHint').textContent = `默认模型 ${p.model} · 端点 ${p.base_url}`;
  $('keyHint').textContent = `环境变量 ${p.key_env} 也可提供`;
  if (!$('model').value) $('model').placeholder = `留空 → ${p.model}`;
}
$('provider').onchange = updateProviderHint;

// ---------------- 配置存取 (localStorage) ----------------
function gatherCfg() {
  return {
    provider: $('provider').value,
    model: $('model').value,
    api_key: $('apiKey').value,
    base_url: $('baseUrl').value,
    temperature: $('temperature').value,
    mock: $('mock').checked,
    use_codeql: $('useCodeql').checked,
    codeql_lang: $('codeqlLang').value,
    codeql_build_command: $('codeqlBuild').value,
    use_symbolic: $('useSymbolic').checked,
    use_sandbox: $('useSandbox').checked,
  };
}
function loadCfg() {
  const s = localStorage.getItem('sg_cfg');
  if (!s) return;
  try {
    const c = JSON.parse(s);
    $('provider').value = c.provider || 'glm';
    $('model').value = c.model || '';
    $('apiKey').value = c.api_key || '';
    $('baseUrl').value = c.base_url || '';
    $('temperature').value = c.temperature || '0.1';
    $('mock').checked = !!c.mock;
    $('useCodeql').checked = !!c.use_codeql;
    $('codeqlLang').value = c.codeql_lang || '';
    $('codeqlBuild').value = c.codeql_build_command || '';
    $('useSymbolic').checked = !!c.use_symbolic;
    $('useSandbox').checked = !!c.use_sandbox;
    updateProviderHint();
  } catch (e) {}
}
$('saveCfg').onclick = () => {
  localStorage.setItem('sg_cfg', JSON.stringify(gatherCfg()));
  showToast('cfgToast', 'ok', '配置已保存到本地浏览器');
};

function showToast(id, kind, msg) {
  const el = $(id);
  el.className = 'toast ' + kind;
  el.textContent = msg;
  setTimeout(() => { el.className = 'toast'; }, 4000);
}

// ---------------- 扫描 ----------------
$('loadSample').onclick = () => { $('target').value = './samples/cpp_project'; };

$('startScan').onclick = async () => {
  const target = $('target').value.trim();
  if (!target) { showToast('scanToast', 'err', '请填写扫描目标路径'); return; }
  const payload = { ...gatherCfg(), target };
  $('startScan').disabled = true;
  $('console').innerHTML = '';
  $('scanState').innerHTML = '<span class="spinner"></span>';
  const r = await fetch('/api/scan', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  const d = await r.json();
  if (!d.ok) {
    showToast('scanToast', 'err', d.error || '启动失败');
    $('startScan').disabled = false;
    $('scanState').innerHTML = '';
    return;
  }
  showToast('scanToast', 'ok', '扫描已启动…');
  poll();
};

function poll() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const r = await fetch('/api/status');
    const d = await r.json();
    renderLogs(d.logs);
    if (d.done) {
      clearInterval(pollTimer);
      $('startScan').disabled = false;
      $('scanState').innerHTML = '';
      if (d.error) {
        showToast('scanToast', 'err', '扫描出错, 见日志');
        appendLog('[错误] ' + d.error, 'err');
      } else if (d.report) {
        showToast('scanToast', 'ok', '扫描完成! 切换到「报告」标签查看');
        renderReport(d.report);
      }
    }
  }, 600);
}

function renderLogs(logs) {
  const c = $('console');
  c.innerHTML = '';
  logs.forEach(l => {
    const span = document.createElement('span');
    span.className = 'ln';
    if (/^\[\d\/\d\]/.test(l)) span.classList.add('step');
    if (l.includes('符号:') || l.includes('沙箱')) span.classList.add('sym');
    span.textContent = l;
    c.appendChild(span);
  });
  c.scrollTop = c.scrollHeight;
}
function appendLog(text, cls) {
  const c = $('console');
  const span = document.createElement('span');
  span.className = 'ln'; if (cls) span.style.color = 'var(--crit)';
  span.textContent = text; c.appendChild(span); c.scrollTop = c.scrollHeight;
}

// ---------------- 报告渲染 ----------------
const SEV_LABEL = { critical: '严重', high: '高危', medium: '中危', low: '低危', unknown: '未知' };
const SYM_LABEL = { reachable: '✅ 可达', unreachable: '❌ 不可达(误报)', unknown: '⚠️ 未定', 'not-applicable': '' };

function esc(s) { return (s||'').replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

function renderReport(rep) {
  $('reportEmpty').style.display = 'none';
  const box = $('reportContent');
  box.style.display = 'block';
  const s = rep.summary;
  const sym = s.symbolic || {};

  let html = '';
  // 统计卡片
  html += `<div class="stats">
    <div class="stat"><div class="num">${s.total_findings}</div><div class="lab">发现总数</div></div>
    <div class="stat"><div class="num" style="color:var(--crit)">${s.exploitable}</div><div class="lab">可利用</div></div>
    <div class="stat"><div class="num" style="color:var(--accent)">${s.dependencies_scanned}</div><div class="lab">扫描依赖</div></div>
    <div class="stat"><div class="num" style="color:var(--ok)">${sym.sandbox_validated||0}</div><div class="lab">沙箱实证</div></div>
  </div>`;

  // 严重程度 + 符号执行
  html += '<div class="sevbar">';
  for (const [k, v] of Object.entries(s.by_severity || {})) {
    html += `<span class="chip ${k}">${SEV_LABEL[k]||k}: ${v}</span>`;
  }
  if (sym.reachable || sym.unreachable || sym.unknown) {
    html += `<span class="chip">符号执行 → 可达 ${sym.reachable||0} · 误报 ${sym.unreachable||0} · 未定 ${sym.unknown||0}</span>`;
  }
  html += '</div>';

  // 依赖清单
  if (rep.dependencies && rep.dependencies.length) {
    html += `<div class="card"><h2><span class="dot"></span>依赖清单 (${rep.dependencies.length})</h2>
      <table class="deps-table"><tr><th>库</th><th>版本</th><th>语言</th><th>来源</th></tr>`;
    rep.dependencies.forEach(d => {
      html += `<tr><td>${esc(d.library)}</td><td>${esc(d.version)||'-'}</td><td>${d.language}</td><td>${esc((d.source_file||'').split(/[\\/]/).pop())}</td></tr>`;
    });
    html += '</table></div>';
  }

  // 漏洞列表
  html += `<div class="card"><h2><span class="dot"></span>漏洞发现 (${rep.findings.length})</h2>`;
  if (!rep.findings.length) html += '<div class="empty">未发现可疑数据流</div>';
  rep.findings.forEach((f, i) => { html += findingHtml(f, i); });
  html += '</div>';

  box.innerHTML = html;
  // 折叠展开
  box.querySelectorAll('.finding-head').forEach(h => {
    h.onclick = () => h.parentElement.classList.toggle('open');
  });
}

function findingHtml(f, i) {
  const fl = f.flow, v = f.verdict, sym = f.symbolic;
  const sev = v.severity || 'unknown';
  let badges = '';
  if (sym && sym.status && sym.status !== 'not-applicable') {
    badges += `<span class="sym-badge ${sym.status}">${SYM_LABEL[sym.status]||sym.status}</span>`;
    if (sym.sandbox_validated) badges += `<span class="sym-badge sandbox">🧪 沙箱实证</span>`;
  }
  let body = '';
  body += kv('文件', `<code>${esc(fl.file)}:${fl.sink_line}</code>`);
  body += kv('数据流', `<code>${esc(fl.source)}</code> <span class="flow-arrow">→</span> <code>${esc(fl.sink)}</code>`);
  body += kv('CWE', `${esc(v.cwe)||'-'} · 可利用: ${v.exploitable?'是':'否'} · 置信度 ${(v.confidence||0).toFixed(2)}`);
  if (fl.library) body += kv('第三方库', `<code>${esc(fl.library)}</code>`);
  if (fl.key_path && fl.key_path.length) body += kv('传播链', fl.key_path.map(esc).join(' <span class="flow-arrow">→</span> '));
  if (f.knowledge) body += kv('知识库', `${esc(f.knowledge.library)} (${f.knowledge.category}, ${f.knowledge.cwe})`);
  if (sym && sym.status && sym.status !== 'not-applicable') {
    let symTxt = `引擎 ${esc(sym.engine)} · ${SYM_LABEL[sym.status]||sym.status}`;
    body += kv('符号执行', symTxt);
    if (sym.poc_input) body += kv('PoC 输入', `<code>${esc(sym.poc_input)}</code>`);
    if (sym.sandbox_evidence) body += kv('沙箱', esc(sym.sandbox_evidence));
  }
  if (fl.code_snippet) body += `<pre>${esc(fl.code_snippet)}</pre>`;
  body += kv('研判理由', esc(v.reason));

  return `<div class="finding">
    <div class="finding-head">
      <span class="sev-pill ${sev}">${SEV_LABEL[sev]||sev}</span>
      <span class="finding-title">${esc(v.vulnerability)}</span>
      ${badges}
      <span class="finding-meta">${fl.language}</span>
    </div>
    <div class="finding-body">${body}</div>
  </div>`;
}
function kv(k, v) { return `<div class="kv"><span class="k">${k}</span><span>${v}</span></div>`; }

init();
