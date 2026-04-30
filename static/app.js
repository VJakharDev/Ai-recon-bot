/**
 * app.js — Bug Bounty Recon Assistant frontend logic
 */

const API = '';
let currentScanId = null;
let wsConnection = null;
let isStreaming = false;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const domainInput     = $('domain-input');
const btnStartScan    = $('btn-start-scan');
const progressPanel   = $('progress-panel');
const progressBar     = $('progress-bar');
const progressPct     = $('progress-pct');
const progressTask    = $('progress-task');
const progressDomain  = $('progress-domain');
const progressStats   = $('progress-stats');
const scanHistory     = $('scan-history');
const welcomeScreen   = $('welcome-screen');
const resultsPanel    = $('results-panel');
const chatMessages    = $('chat-messages');
const chatInput       = $('chat-input');
const btnSend         = $('btn-send');
const modelName       = $('model-name');
const statusDot       = $('status-dot');
const statusText      = $('status-text');

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  checkHealth();
  loadScanHistory();
  setupEventListeners();
});

async function checkHealth() {
  try {
    const res = await fetch(`${API}/api/health`);
    const data = await res.json();

    // ── Top bar status dot ──
    statusDot.className = 'status-dot ok';
    statusText.textContent = data.api_connected ? 'Connected' : 'API key error';
    if (!data.api_connected) statusDot.className = 'status-dot error';
    modelName.textContent = data.model_selected?.split('/').pop() || '—';

    // ── Topbar tool pill strip ──
    const TOOLS_META = [
      { id: 'subfinder',   label: 'subfinder' },
      { id: 'amass',       label: 'amass'      },
      { id: 'httpx',       label: 'httpx'      },
      { id: 'gau',         label: 'gau'        },
      { id: 'waybackurls', label: 'wayback'    },
      { id: 'naabu',       label: 'naabu'      },
      { id: 'nuclei',      label: 'nuclei'     },
    ];
    const available = new Set(data.tools_available || []);
    const topbarTools = $('topbar-tools');
    if (topbarTools) {
      topbarTools.innerHTML = TOOLS_META.map(t => {
        const ok = available.has(t.id);
        return `<span class="tool-pill ${ok ? 'ok' : 'miss'}" title="${ok ? t.id + ' ready' : t.id + ' not found'}">
          <span class="tool-pill-dot"></span>${t.label}
        </span>`;
      }).join('') +
      `<span class="tool-pill ai" title="LLM: ${data.model_selected}">
        <span class="tool-pill-dot"></span>LLM
      </span>`;
    }

    // ── Welcome screen per-card badges ──
    TOOLS_META.forEach(t => {
      const badge = $(`badge-${t.id}`);
      if (!badge) return;
      const ok = available.has(t.id);
      badge.textContent  = ok ? '✓ ready' : '✗ missing';
      badge.className    = `tool-badge ${ok ? 'ok' : 'miss'}`;
      // Dim the card if tool is missing
      const card = badge.closest('.feature-card');
      if (card) card.style.opacity = ok ? '1' : '0.55';
    });

    // AI badge
    const aiBadge = $('badge-ai');
    if (aiBadge) {
      const aiOk = data.api_connected;
      aiBadge.textContent = aiOk ? '✓ ready' : '✗ no API key';
      aiBadge.className   = `tool-badge ${aiOk ? 'ok' : 'miss'}`;
    }

  } catch (err) {
    statusDot.className = 'status-dot error';
    statusText.textContent = 'Server offline';
  }
}

// ── Event Listeners ───────────────────────────────────────────────────────────
function setupEventListeners() {
  btnStartScan.addEventListener('click', startScan);
  domainInput.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });

  btnSend.addEventListener('click', sendChat);
  chatInput.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); }
  });
  chatInput.addEventListener('input', () => {
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 120) + 'px';
  });

  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  document.querySelectorAll('.hint-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      chatInput.value = chip.dataset.hint;
      chatInput.dispatchEvent(new Event('input'));
      sendChat();
    });
  });

  $('btn-refresh-scans').addEventListener('click', loadScanHistory);
  $('btn-download-md').addEventListener('click', () => downloadReport('markdown'));
  $('btn-download-json').addEventListener('click', () => downloadReport('json'));
  $('btn-stop-scan').addEventListener('click', stopScan);

  $('hosts-filter').addEventListener('input', filterHosts);
  $('hosts-score-filter').addEventListener('change', filterHosts);
}

// ── Scan ──────────────────────────────────────────────────────────────────────
async function startScan() {
  const domain = domainInput.value.trim();
  if (!domain) { domainInput.focus(); return; }

  btnStartScan.disabled = true;
  btnStartScan.textContent = 'Launching...';

  try {
    const amassEnabled = $('amass-toggle').checked;
    const res = await fetch(`${API}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, options: { amass_enabled: amassEnabled } }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Scan failed to start');

    currentScanId = data.scan_id;
    domainInput.value = '';
    showResultsPanel(domain, 'running');
    showProgressPanel(domain);
    connectWebSocket(data.scan_id);
    loadScanHistory();
  } catch (err) {
    alert(`Error: ${err.message}`);
  } finally {
    btnStartScan.disabled = false;
    btnStartScan.innerHTML = '<span class="btn-icon">⚡</span> Launch Recon';
  }
}

function connectWebSocket(scanId) {
  if (wsConnection) wsConnection.close();

  const wsUrl = `ws://${location.host}/ws/scan/${scanId}`;
  wsConnection = new WebSocket(wsUrl);

  wsConnection.onmessage = e => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'progress') {
      updateProgress(msg.progress, msg.task, msg.message);
    } else if (msg.type === 'complete') {
      hideScanStop();
      updateProgress(100, 'Scan complete!', '');
      setTimeout(() => loadScanResults(scanId), 800);
    } else if (msg.type === 'stopped') {
      hideScanStop();
      updateProgress(msg.progress, '⏹ Stopped — finalizing partial results...', '');
      setTimeout(() => loadScanResults(scanId), 1200);
    } else if (msg.type === 'error') {
      hideScanStop();
      progressTask.textContent = `Error: ${msg.message}`;
    }
  };

  wsConnection.onerror = () => {
    // Fallback: poll status
    pollScanStatus(scanId);
  };
}

function pollScanStatus(scanId) {
  const interval = setInterval(async () => {
    try {
      const res = await fetch(`${API}/api/scan/${scanId}/status`);
      const data = await res.json();
      updateProgress(data.progress, data.current_task, '');
      if (data.status === 'complete') {
        clearInterval(interval);
        hideScanStop();
        setTimeout(() => loadScanResults(scanId), 800);
      } else if (data.status === 'stopped') {
        clearInterval(interval);
        hideScanStop();
        setTimeout(() => loadScanResults(scanId), 800);
      } else if (data.status === 'failed') {
        clearInterval(interval);
        hideScanStop();
        progressTask.textContent = 'Scan failed';
      }
    } catch { clearInterval(interval); }
  }, 3000);
}

function updateProgress(pct, task, msg) {
  progressBar.style.width = `${pct}%`;
  progressPct.textContent = `${pct}%`;
  progressTask.textContent = task || '';
  if (msg) progressStats.textContent = msg;
}

async function loadScanResults(scanId) {
  try {
    const res = await fetch(`${API}/api/scan/${scanId}`);
    const scan = await res.json();
    currentScanId = scanId;
    renderScanResults(scan);
    loadScanHistory();
    progressPanel.style.display = 'none';
  } catch (err) {
    console.error('Failed to load scan:', err);
  }
}

// ── Render Results ────────────────────────────────────────────────────────────
function renderScanResults(scan) {
  showResultsPanel(scan.domain, scan.status);

  // Status badge
  const badge = $('results-status-badge');
  badge.textContent = scan.status;
  badge.className = `results-status-badge ${scan.status}`;

  // Stats bar
  $('stats-bar').innerHTML = [
    { label: 'Subdomains', value: scan.subdomains?.length || 0 },
    { label: 'Live Hosts', value: scan.live_hosts?.length || 0 },
    { label: 'URLs', value: scan.urls?.length || 0 },
    { label: 'Ports', value: scan.open_ports?.length || 0 },
    { label: 'Vulns', value: scan.vulnerabilities?.length || 0 },
    { label: 'HIGH', value: scan.score_summary?.high?.length || 0 },
  ].map(s => `<div class="stat-item">
    <span class="stat-value">${s.value}</span>
    <span class="stat-label">${s.label}</span>
  </div>`).join('');

  // Show download buttons for complete or stopped scans
  if (scan.status === 'complete' || scan.status === 'stopped') {
    $('btn-download-md').style.display = '';
    $('btn-download-json').style.display = '';
  }

  // Render AI analysis
  if (scan.ai_analysis) renderAIAnalysis(scan.ai_analysis);

  // Render each tab
  renderFindings(scan);
  renderHosts(scan.live_hosts || []);
  renderIntel(scan.intel_tags || {});
  renderVulns(scan.vulnerabilities || []);
  renderAttackPaths(scan.attack_paths || []);
}

function renderAIAnalysis(text) {
  chatMessages.innerHTML = '';
  appendMessage('ai', text);
}

function renderFindings(scan) {
  const intel = scan.intel_tags || {};
  const grid = $('findings-grid');
  const items = [
    { label: 'High Priority', value: scan.score_summary?.high?.length || 0, cls: 'high', urls: scan.score_summary?.high || [] },
    { label: 'IDOR Candidates', value: intel.idor_candidates?.length || 0, cls: 'high', urls: intel.idor_candidates || [] },
    { label: 'SSRF Candidates', value: intel.ssrf_candidates?.length || 0, cls: 'high', urls: intel.ssrf_candidates || [] },
    { label: 'Open Redirect', value: intel.open_redirect_candidates?.length || 0, cls: 'medium', urls: intel.open_redirect_candidates || [] },
    { label: 'XSS Candidates', value: intel.xss_candidates?.length || 0, cls: 'medium', urls: intel.xss_candidates || [] },
    { label: 'Auth Exposure', value: intel.auth_exposure_candidates?.length || 0, cls: 'high', urls: intel.auth_exposure_candidates || [] },
    { label: 'High-Value Endpoints', value: intel.high_value_endpoints?.length || 0, cls: 'medium', urls: intel.high_value_endpoints || [] },
    { label: 'Critical Vulns', value: (scan.vulnerabilities || []).filter(v => v.severity === 'critical').length, cls: 'high', urls: [] },
  ];
  grid.innerHTML = items.map(i => `
    <div class="finding-card ${i.cls}">
      <div class="finding-type">${i.label}</div>
      <div class="finding-count">${i.value}</div>
      ${i.urls.slice(0, 3).map(u => `<div class="finding-url">${truncate(u, 60)}</div>`).join('')}
    </div>
  `).join('');
}

let _allHosts = [];
function renderHosts(hosts) {
  _allHosts = hosts;
  renderHostsTable(hosts);
}

function renderHostsTable(hosts) {
  $('hosts-tbody').innerHTML = hosts.map(h => `
    <tr>
      <td class="mono"><a href="${h.url}" target="_blank" style="color:var(--accent);text-decoration:none">${truncate(h.url, 55)}</a></td>
      <td>${statusCodeBadge(h.status_code)}</td>
      <td>${truncate(h.title || '—', 40)}</td>
      <td>${(h.technologies || []).slice(0, 3).join(', ') || '—'}</td>
      <td><span class="score-badge ${h.score}">${h.score}</span></td>
      <td>${(h.intel_tags || []).map(t => `<span class="tag-chip">${t}</span>`).join('')}</td>
    </tr>
  `).join('');
}

function filterHosts() {
  const text = $('hosts-filter').value.toLowerCase();
  const score = $('hosts-score-filter').value;
  const filtered = _allHosts.filter(h => {
    const matchText = !text || h.url.toLowerCase().includes(text) || (h.title || '').toLowerCase().includes(text);
    const matchScore = !score || h.score === score;
    return matchText && matchScore;
  });
  renderHostsTable(filtered);
}

function renderIntel(intel) {
  const categories = [
    { title: 'High-Value Endpoints', icon: '🎯', key: 'high_value_endpoints' },
    { title: 'IDOR Candidates', icon: '🔓', key: 'idor_candidates' },
    { title: 'SSRF Candidates', icon: '🌐', key: 'ssrf_candidates' },
    { title: 'Open Redirect', icon: '↪️', key: 'open_redirect_candidates' },
    { title: 'XSS Candidates', icon: '💉', key: 'xss_candidates' },
    { title: 'Auth Exposure', icon: '🔑', key: 'auth_exposure_candidates' },
    { title: 'Interesting Ports', icon: '🚪', key: 'interesting_ports' },
  ];
  $('intel-grid').innerHTML = categories.map(c => {
    const urls = intel[c.key] || [];
    if (!urls.length) return '';
    return `<div class="intel-card">
      <div class="intel-card-title">${c.icon} ${c.title} <span>${urls.length}</span></div>
      <div class="intel-url-list">
        ${urls.slice(0, 12).map(u => `<div class="intel-url" title="${u}">${truncate(u, 65)}</div>`).join('')}
        ${urls.length > 12 ? `<div class="intel-url" style="color:var(--text-muted)">+${urls.length - 12} more</div>` : ''}
      </div>
    </div>`;
  }).join('');
}

function renderVulns(vulns) {
  if (!vulns.length) {
    $('vulns-list').innerHTML = '<div class="empty-state">No vulnerabilities detected by nuclei</div>';
    return;
  }
  const sorted = [...vulns].sort((a, b) => sevOrder(a.severity) - sevOrder(b.severity));
  $('vulns-list').innerHTML = sorted.map(v => `
    <div class="vuln-card ${v.severity}">
      <div class="vuln-header">
        <span class="vuln-name">${v.name}</span>
        <span class="sev-badge ${v.severity}">${v.severity}</span>
      </div>
      <div class="vuln-meta">${v.template_id} · ${truncate(v.matched_at, 70)}</div>
      ${v.description ? `<div class="vuln-desc">${v.description}</div>` : ''}
    </div>
  `).join('');
}

function renderAttackPaths(paths) {
  if (!paths.length) {
    $('paths-list').innerHTML = '<div class="empty-state">No attack paths generated yet</div>';
    return;
  }
  $('paths-list').innerHTML = paths.map(p => `
    <div class="path-card">
      <div class="path-header">
        <span class="path-type">${p.vulnerability_type}</span>
        <span class="sev-badge ${p.severity}">${p.severity}</span>
        <span class="sev-badge" style="background:rgba(168,85,247,.15);color:#a855f7;border:1px solid rgba(168,85,247,.3)">
          ${p.confidence} confidence
        </span>
      </div>
      <div class="path-target">▶ ${p.target}</div>
      <div class="path-reasoning">${p.reasoning}</div>
      <div class="path-steps">
        ${(p.steps || []).map(s => `<div class="path-step">${s}</div>`).join('')}
      </div>
    </div>
  `).join('');
}

// ── Chat ──────────────────────────────────────────────────────────────────────
async function sendChat() {
  if (!currentScanId || isStreaming) return;
  const msg = chatInput.value.trim();
  if (!msg) return;

  chatInput.value = '';
  chatInput.style.height = 'auto';
  appendMessage('user', msg);
  showTyping();
  btnSend.disabled = true;
  isStreaming = true;

  try {
    const res = await fetch(`${API}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: currentScanId, message: msg }),
    });

    if (!res.ok) throw new Error(await res.text());

    removeTyping();
    const aiMsg = appendMessage('ai', '');
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let fullText = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const data = JSON.parse(line.slice(6));
            if (data.content) {
              fullText += data.content;
              aiMsg.querySelector('.msg-bubble').innerHTML = renderMarkdown(fullText);
              chatMessages.scrollTop = chatMessages.scrollHeight;
            }
          } catch {}
        }
      }
    }
  } catch (err) {
    removeTyping();
    appendMessage('ai', `⚠️ Error: ${err.message}`);
  } finally {
    btnSend.disabled = false;
    isStreaming = false;
  }
}

function appendMessage(role, text) {
  const div = document.createElement('div');
  div.className = `chat-msg ${role}`;
  div.innerHTML = `
    <div class="msg-avatar ${role}">${role === 'ai' ? '◈' : '▸'}</div>
    <div class="msg-bubble">${renderMarkdown(text)}</div>
  `;
  chatMessages.appendChild(div);
  chatMessages.scrollTop = chatMessages.scrollHeight;
  return div;
}

function showTyping() {
  const div = document.createElement('div');
  div.className = 'chat-msg ai';
  div.id = 'typing-indicator';
  div.innerHTML = `
    <div class="msg-avatar ai">◈</div>
    <div class="msg-bubble">
      <div class="typing-indicator">
        <span class="typing-dot"></span>
        <span class="typing-dot"></span>
        <span class="typing-dot"></span>
      </div>
    </div>`;
  chatMessages.appendChild(div);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

function removeTyping() {
  const el = $('typing-indicator');
  if (el) el.remove();
}

// ── Scan History ──────────────────────────────────────────────────────────────
async function loadScanHistory() {
  try {
    const res = await fetch(`${API}/api/scans`);
    const data = await res.json();
    const scans = data.scans || [];
    if (!scans.length) {
      scanHistory.innerHTML = '<div class="empty-state">No scans yet</div>';
      return;
    }
    scanHistory.innerHTML = scans.map(s => `
      <div class="history-item ${s.scan_id === currentScanId ? 'active' : ''}"
           data-id="${s.scan_id}" onclick="loadScanResults('${s.scan_id}')">
        <div class="history-domain">${s.domain}</div>
        <div class="history-meta">
          <span class="history-status ${s.status}">${s.status}</span>
          <span>${formatTime(s.timestamp)}</span>
        </div>
      </div>
    `).join('');
  } catch {}
}

// ── UI Helpers ────────────────────────────────────────────────────────────────
function showResultsPanel(domain, status) {
  welcomeScreen.style.display = 'none';
  resultsPanel.style.display = 'flex';
  resultsPanel.style.flexDirection = 'column';
  $('results-domain').textContent = domain;
}

function showProgressPanel(domain) {
  progressPanel.style.display = 'block';
  progressDomain.textContent = domain;
  updateProgress(0, 'Initializing...');
  // Reset stop button
  const btnStop = $('btn-stop-scan');
  if (btnStop) { btnStop.disabled = false; btnStop.textContent = '⏹ Stop Scan'; }
}

function hideScanStop() {
  const btnStop = $('btn-stop-scan');
  if (btnStop) { btnStop.disabled = true; btnStop.textContent = 'Stopped'; }
}

async function stopScan() {
  if (!currentScanId) return;
  const btnStop = $('btn-stop-scan');
  if (btnStop) { btnStop.disabled = true; btnStop.textContent = '⏳ Stopping...'; }
  try {
    const res = await fetch(`${API}/api/scan/${currentScanId}/stop`, { method: 'POST' });
    if (!res.ok) {
      const err = await res.json();
      alert(`Could not stop: ${err.detail}`);
      if (btnStop) { btnStop.disabled = false; btnStop.textContent = '⏹ Stop Scan'; }
    }
    // WS 'stopped' event handles the rest
  } catch (e) {
    alert(`Stop failed: ${e.message}`);
    if (btnStop) { btnStop.disabled = false; btnStop.textContent = '⏹ Stop Scan'; }
  }
}

function switchTab(tabId) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === `tab-${tabId}`));
}

async function downloadReport(format) {
  if (!currentScanId) return;
  const url = format === 'json'
    ? `${API}/api/report/${currentScanId}/json`
    : `${API}/api/report/${currentScanId}`;
  window.open(url, '_blank');
}

// ── Markdown Renderer (lightweight) ──────────────────────────────────────────
function renderMarkdown(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) =>
      `<pre><code class="lang-${lang}">${code.trim()}</code></pre>`)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h2>$1</h2>')
    .replace(/^\- (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>(\n)?)+/g, m => `<ul>${m}</ul>`)
    .replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
    .replace(/^---$/gm, '<hr>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/^(?!<[h|u|p|l|p|h|o|c])/gm, '')
    .replace(/\n/g, '<br>');
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function truncate(s, n) {
  if (!s) return '';
  return s.length <= n ? s : '...' + s.slice(-(n - 3));
}

function statusCodeBadge(code) {
  const color = code >= 500 ? 'var(--red)' : code >= 400 ? 'var(--orange)' : code >= 300 ? 'var(--yellow)' : 'var(--accent)';
  return `<span style="color:${color};font-family:var(--mono)">${code || '?'}</span>`;
}

function sevOrder(s) {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s?.toLowerCase()] ?? 5;
}

function formatTime(ts) {
  try {
    const d = new Date(ts + 'Z');
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch { return ts || ''; }
}
