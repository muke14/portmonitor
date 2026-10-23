/* PortMonitor – Frontend App  */
'use strict';

// ─── State ───────────────────────────────────────────────────────────────────
const state = {
  token:          localStorage.getItem('pm_token')  || null,
  username:       localStorage.getItem('pm_user')   || null,
  theme:          localStorage.getItem('pm_theme')  || 'dark',
  machines:       [],
  localHost:      null,   // { hostname, ip } — the server machine
  // active machine session
  activeMachine:  null,   // { name, host } or { name:'Quick Scan', host, ephemeral:true }
  // scan data split by protocol
  tcp:  { results:[], running:false, ws:null, sortKey:'port', sortDir:'asc' },
  udp:  { results:[], running:false, ws:null, sortKey:'port', sortDir:'asc' },
  activeProto:    'tcp',  // which port-list tab is visible
  charts:         {},
};

// ─── Boot ────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.body.className = state.theme;
  buildUI();
  if (state.token) showMachinesPage();
  else             showAuthPage();
});

// ═══════════════════════════════════════════════════════════════════════════════
//  HTML BUILDER
// ═══════════════════════════════════════════════════════════════════════════════
function buildUI() {
  document.body.innerHTML = `

  <!-- ── AUTH PAGE ─────────────────────────────────────────────────────── -->
  <div id="page-auth">
    <div class="auth-card">
      <div class="auth-logo">${iconRadar(28)} PortMonitor</div>
      <div class="auth-tabs">
        <button class="auth-tab active" data-tab="login">Sign In</button>
        <button class="auth-tab" data-tab="register">Register</button>
      </div>
      <div id="auth-form-login">
        <div class="form-group"><label>Username</label>
          <input class="form-input" id="login-user" placeholder="username" autocomplete="username"/>
        </div>
        <div class="form-group"><label>Password</label>
          <input class="form-input" id="login-pass" type="password" placeholder="••••••••" autocomplete="current-password"/>
        </div>
        <button class="btn btn-primary btn-full" id="btn-login">Sign In</button>
        <div id="login-msg"></div>
      </div>
      <div id="auth-form-register" style="display:none">
        <div class="form-group"><label>Username</label>
          <input class="form-input" id="reg-user" placeholder="choose a username"/>
        </div>
        <div class="form-group"><label>Password</label>
          <input class="form-input" id="reg-pass" type="password" placeholder="At least 12 characters" autocomplete="new-password"/>
        </div>
        <button class="btn btn-primary btn-full" id="btn-register">Create Account</button>
        <div id="reg-msg"></div>
      </div>
    </div>
  </div>

  <!-- ── MACHINES PAGE (landing after login) ───────────────────────────── -->
  <div id="page-machines" style="display:none">
    <div class="topbar">
      <div class="topbar-logo">${iconRadar(20)} PortMonitor</div>
      <div class="topbar-right">
        <button class="theme-toggle" id="theme-toggle-m">🌙 Dark</button>
        <div class="user-badge" id="user-badge-m">—</div>
        <button class="btn btn-outline btn-sm" id="btn-logout-m">Logout</button>
      </div>
    </div>
    <div class="machines-page-body">
      <div class="machines-hero">
        <h1>Select a Machine to Monitor</h1>
        <p class="text-muted">Choose a saved machine, monitor this server, or scan any host you are authorized to assess.</p>
      </div>

      <!-- ── THIS MACHINE card (the server running PortMonitor) ── -->
      <div class="this-machine-card" id="this-machine-card">
        <div class="tm-icon">${iconRadar(28)}</div>
        <div class="tm-body">
          <div class="tm-title">This Machine <span class="badge badge-accent">server</span></div>
          <div class="tm-host text-muted" id="tm-host-label">Detecting…</div>
          <div style="display:flex;align-items:center;gap:.5rem;flex-wrap:wrap">
            <span class="os-badge" id="tm-os-badge" style="display:none">—</span>
            <span class="tm-sub text-muted">Monitor the host running this PortMonitor instance.</span>
          </div>
        </div>
        <button class="btn btn-primary" id="btn-this-machine">▶ Monitor</button>
      </div>

      <!-- Quick scan card (ephemeral, any host) -->
      <div class="quick-scan-card" id="quick-scan-card">
        <div class="qs-icon">${iconRadar(28)}</div>
        <div class="qs-body">
          <div class="qs-title">Quick Scan <span class="badge badge-outline">not saved</span></div>
          <div class="qs-sub text-muted">Scan any host once without saving it to your machine list.</div>
          <div class="qs-row">
            <input class="form-input qs-input" id="qs-host" placeholder="IP or hostname e.g. 192.168.1.1"/>
            <button class="btn btn-primary" id="btn-quick-scan">▶ Scan Now</button>
          </div>
          <div id="qs-msg"></div>
        </div>
      </div>

      <!-- Saved machines grid -->
      <div class="section-header" style="margin-top:1.5rem">Saved Machines</div>
      <div class="machines-grid" id="machines-grid">
        <div class="empty-state" style="grid-column:1/-1">
          <div class="icon">🖥</div><div>No machines saved yet</div>
        </div>
      </div>

      <!-- Add machine form -->
      <div class="section-header" style="margin-top:1.5rem">Add Machine</div>
      <div class="add-machine-form">
        <div class="form-group" style="flex:1;min-width:140px"><label>Machine Name</label>
          <input class="form-input" id="mc-name" placeholder="e.g. Web Server"/>
        </div>
        <div class="form-group" style="flex:1;min-width:140px"><label>Host / IP</label>
          <input class="form-input" id="mc-host" placeholder="e.g. 192.168.1.10"/>
        </div>
        <button class="btn btn-primary" id="btn-add-machine" style="align-self:flex-end">+ Add</button>
        <div id="mc-msg" style="align-self:flex-end"></div>
      </div>
    </div>
  </div>

  <!-- ── MONITOR PAGE (per-machine dashboard + port tabs) ──────────────── -->
  <div id="page-monitor" style="display:none">
    <div class="topbar">
      <div class="topbar-logo">${iconRadar(20)} PortMonitor</div>
      <nav class="topbar-nav">
        <button class="nav-btn active" data-tab="dashboard">Dashboard</button>
        <button class="nav-btn" data-tab="tcp">TCP Ports</button>
        <button class="nav-btn" data-tab="udp">UDP Ports</button>
      </nav>
      <div class="topbar-right">
        <div class="machine-badge" id="monitor-machine-badge">—</div>
        <button class="btn btn-outline btn-sm" id="btn-export">⬇ Export</button>
        <button class="theme-toggle" id="theme-toggle-mon">🌙 Dark</button>
        <button class="btn btn-outline btn-sm" id="btn-back">← Machines</button>
        <button class="btn btn-outline btn-sm" id="btn-logout-mon">Logout</button>
      </div>
    </div>

    <div class="monitor-body">

      <!-- ── DASHBOARD TAB ──────────────────────────────────────────────── -->
      <div class="tab-panel active" id="tab-dashboard">

        <!-- Live status bar -->
        <div class="live-bar">
          <span class="live-dot pulse" id="live-dot"></span>
          <span class="live-label" id="live-label">Connecting…</span>
          <span class="live-sep">·</span>
          <span class="text-muted text-sm" id="live-sweep">Sweep 0</span>
          <span class="live-sep">·</span>
          <span class="text-muted text-sm" id="live-updated">—</span>
          <div style="margin-left:auto;display:flex;align-items:center;gap:.5rem">
            <button id="btn-refresh" onclick="manualRefresh()" style="background:var(--surface2);border:1px solid var(--border);border-radius:5px;color:var(--text);padding:.3rem .7rem;font-size:.82rem;cursor:pointer" title="Stop current scan and restart immediately">↺ Refresh</button>
            <span class="scan-label">Ports</span>
            <input id="scan-start" type="number" min="1" max="65535" value="1" aria-label="First port" style="width:76px;background:var(--surface2);border:1px solid var(--border);border-radius:5px;color:var(--text);padding:.3rem .5rem;font-size:.82rem"/>
            <span class="scan-label">to</span>
            <input id="scan-end" type="number" min="1" max="65535" value="1024" aria-label="Last port" style="width:76px;background:var(--surface2);border:1px solid var(--border);border-radius:5px;color:var(--text);padding:.3rem .5rem;font-size:.82rem"/>
            <span class="scan-label">Timeout</span>
            <input id="scan-timeout" type="number" step="0.1" min="0.1" max="3" value="0.7" style="width:60px;background:var(--surface2);border:1px solid var(--border);border-radius:5px;color:var(--text);padding:.3rem .5rem;font-size:.82rem"/>
            <div class="progress-inline">
              <div class="progress-bar-outer" style="width:120px"><div class="progress-bar-inner" id="progress-bar"></div></div>
              <span class="progress-txt" id="progress-txt" style="min-width:60px">—</span>
            </div>
          </div>
        </div>

        <!-- Stat cards -->
        <div class="stat-grid" id="stat-grid">
          ${statCard('TCP Open',         '—', 'v-open',     'Responding TCP ports',         'stat-open')}
          ${statCard('TCP Closed',       '—', 'v-closed',   'Not responding TCP ports',     'stat-closed')}
          ${statCard('TCP Filtered',     '—', 'v-exposed',  'Not confirmed open or closed', 'stat-tcp-filtered')}
          ${statCard('UDP Open/Filtered','—', 'v-udp',      'UDP ports responding',          'stat-udp')}
          ${statCard('UDP Closed',       '—', 'v-closed',   'UDP ports not responding',      'stat-udp-closed')}
          ${statCard('Internet Exposure','Not measured', 'v-exposed',  'Requires an external vantage point', 'stat-exposed')}
          ${statCard('Critical Risk',    '—', 'v-critical', 'Critical risk across TCP+UDP',  'stat-critical')}
          <div class="stat-card" id="stat-os-card">
            <div class="label">Operating System</div>
            <div class="value os-stat-value" id="stat-os-name" style="font-size:1rem;padding-top:.3rem">—</div>
            <div class="sub" id="stat-os-version">Detecting…</div>
          </div>
        </div>

        <!-- Charts -->
        <div class="charts-row">
          <div class="chart-card">
            <h3>TCP Status</h3>
            <div class="chart-wrap"><canvas id="chart-status"></canvas></div>
          </div>
          <div class="chart-card">
            <h3>UDP Status</h3>
            <div class="chart-wrap"><canvas id="chart-udp-status"></canvas></div>
          </div>
          <div class="chart-card">
            <h3>Risk Breakdown</h3>
            <div class="chart-wrap"><canvas id="chart-risk"></canvas></div>
          </div>
          <div class="chart-card">
            <h3>Top Open Services</h3>
            <div class="chart-wrap"><canvas id="chart-services"></canvas></div>
          </div>
          <div class="chart-card">
            <h3>Port Range Activity</h3>
            <div class="chart-wrap"><canvas id="chart-ranges"></canvas></div>
          </div>
        </div>

        <!-- Critical ports summary table -->
        <div class="table-wrap" style="max-height:300px">
          <div class="table-toolbar">
            <span style="font-weight:600;font-size:.85rem">Critical &amp; High Risk Ports</span>
          </div>
          <div class="table-scroll" style="max-height:240px">
            <table class="port-table" id="critical-table">
              <thead><tr>
                <th>Port</th><th>Proto</th><th>Service</th>
                <th>Risk</th><th>Internet exposure</th><th>Banner / Notes</th>
              </tr></thead>
              <tbody id="critical-tbody">
                <tr><td colspan="6" class="empty-state">Run a scan to see results</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ── TCP PORTS TAB ──────────────────────────────────────────────── -->
      <div class="tab-panel" id="tab-tcp">
        <div class="table-wrap" style="flex:1">
          <div class="table-toolbar">
            <span class="proto-badge proto-tcp">TCP</span>
            <input class="search-input" id="tcp-search" placeholder="Search port, service, status…"/>
            <select id="tcp-filter-status" class="filter-select">
              <option value="all">All Status</option>
              <option value="open">Open</option>
              <option value="filtered">Filtered</option>
              <option value="closed">Closed</option>
            </select>
            <select id="tcp-filter-risk" class="filter-select">
              <option value="all">All Risk</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <span class="table-count" id="tcp-count">0 ports</span>
          </div>
          <div class="table-scroll">
            <table class="port-table" id="tcp-table">
              <thead><tr>
                <th data-col="port" class="sorted">Port <span class="sort-arrow">▲</span></th>
                <th data-col="service">Service <span class="sort-arrow">↕</span></th>
                <th data-col="status">Status <span class="sort-arrow">↕</span></th>
                <th data-col="risk">Risk <span class="sort-arrow">↕</span></th>
                <th>Internet exposure</th>
                <th>Banner / Notes</th>
              </tr></thead>
              <tbody id="tcp-tbody">
                <tr><td colspan="6" class="empty-state"><div class="icon">📡</div><div>Click ▶ Scan TCP to start</div></td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ── UDP PORTS TAB ──────────────────────────────────────────────── -->
      <div class="tab-panel" id="tab-udp">
        <div class="table-wrap" style="flex:1">
          <div class="table-toolbar">
            <span class="proto-badge proto-udp">UDP</span>
            <input class="search-input" id="udp-search" placeholder="Search port, service, status…"/>
            <select id="udp-filter-status" class="filter-select">
              <option value="all">All Status</option>
              <option value="open">Open</option>
              <option value="open|filtered">Open|Filtered</option>
              <option value="closed">Closed</option>
            </select>
            <select id="udp-filter-risk" class="filter-select">
              <option value="all">All Risk</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <span class="table-count" id="udp-count">0 ports</span>
          </div>
          <div class="table-scroll">
            <table class="port-table" id="udp-table">
              <thead><tr>
                <th data-col="port" class="sorted">Port <span class="sort-arrow">▲</span></th>
                <th data-col="service">Service <span class="sort-arrow">↕</span></th>
                <th data-col="status">Status <span class="sort-arrow">↕</span></th>
                <th data-col="risk">Risk <span class="sort-arrow">↕</span></th>
                <th>Internet exposure</th>
                <th>Banner / Notes</th>
              </tr></thead>
              <tbody id="udp-tbody">
                <tr><td colspan="6" class="empty-state"><div class="icon">📡</div><div>Click ▶ Scan UDP to start</div></td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

    </div><!-- /monitor-body -->
  </div><!-- /page-monitor -->
  `;

  wireAuth();
  wireMachinesPage();
  wireMonitorPage();
}

// ─── Icons ───────────────────────────────────────────────────────────────────
function iconRadar(s=20) {
  return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/><line x1="2" y1="12" x2="22" y2="12"/></svg>`;
}

function statCard(label, val, cls, sub, id) {
  return `<div class="stat-card"><div class="label">${label}</div><div class="value ${cls}" id="${id}">${val}</div><div class="sub">${sub}</div></div>`;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PAGE NAVIGATION
// ═══════════════════════════════════════════════════════════════════════════════
function showAuthPage() {
  document.getElementById('page-auth').style.display     = '';
  document.getElementById('page-machines').style.display = 'none';
  document.getElementById('page-monitor').style.display  = 'none';
  destroyCharts();
}

function showMachinesPage() {
  document.getElementById('page-auth').style.display     = 'none';
  document.getElementById('page-machines').style.display = '';
  document.getElementById('page-monitor').style.display  = 'none';
  document.getElementById('user-badge-m').textContent    = state.username || '';
  updateThemeBtns();
  loadMachines();
  loadLocalHost();   // populate "This Machine" card
}

function showMonitorPage(machine) {
  // Stop any existing scans from a previous machine
  stopAllScans();

  // Set new machine AFTER stopAllScans (which clears activeMachine)
  state.activeMachine = machine;

  document.getElementById('page-auth').style.display     = 'none';
  document.getElementById('page-machines').style.display = 'none';
  document.getElementById('page-monitor').style.display  = '';
  document.getElementById('monitor-machine-badge').textContent =
    `${machine.name}  ·  ${machine.host}`;
  updateThemeBtns();

  // Fresh scan state — new machine, wipe old results
  state.tcp = { results:[], running:false, ws:null, sortKey:'port', sortDir:'asc', map:{} };
  state.udp = { results:[], running:false, ws:null, sortKey:'port', sortDir:'asc', map:{} };

  destroyCharts();
  initCharts();
  refreshDashboard();
  switchMonitorTab('dashboard');

  // Populate OS stat card — use cached value instantly, then fetch if missing
  const osName    = document.getElementById('stat-os-name');
  const osVersion = document.getElementById('stat-os-version');
  if (machine.os) {
    if (osName)    osName.textContent    = machine.os;
    if (osVersion) osVersion.textContent = machine.os_version || '';
  } else {
    if (osName)    osName.textContent    = '—';
    if (osVersion) osVersion.textContent = 'Detecting…';
    fetchAndCacheOS(machine, (os, ver) => {
      if (osName)    osName.textContent    = os;
      if (osVersion) osVersion.textContent = ver;
      // Also update topbar badge
      const badge = document.getElementById('monitor-machine-badge');
      if (badge) badge.textContent = `${machine.name}  ·  ${machine.host}  ·  ${os}`;
    });
  }

  // Update topbar badge with cached OS if already known
  if (machine.os) {
    const badge = document.getElementById('monitor-machine-badge');
    if (badge) badge.textContent = `${machine.name}  ·  ${machine.host}  ·  ${machine.os}`;
  }

  // Start both protocols using the selected, bounded port range.
  startScan('tcp');
  startScan('udp');
}

// ─── Monitor tab switching ────────────────────────────────────────────────────
function switchMonitorTab(tab) {
  document.querySelectorAll('#page-monitor .nav-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('#page-monitor .tab-panel').forEach(p =>
    p.classList.toggle('active', p.id === `tab-${tab}`));
  state.activeProto = tab === 'tcp' ? 'tcp' : tab === 'udp' ? 'udp' : 'dashboard';
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTH WIRING
// ═══════════════════════════════════════════════════════════════════════════════
function wireAuth() {
  document.querySelectorAll('.auth-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.auth-tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('auth-form-login').style.display    = btn.dataset.tab === 'login'    ? '' : 'none';
      document.getElementById('auth-form-register').style.display = btn.dataset.tab === 'register' ? '' : 'none';
    });
  });

  document.getElementById('btn-login').addEventListener('click', async () => {
    const u = document.getElementById('login-user').value.trim();
    const p = document.getElementById('login-pass').value;
    const msg = document.getElementById('login-msg');
    if (!u || !p) { showMsg(msg, 'Username and password required', 'error'); return; }
    const res = await api('/api/login', {method:'POST', body:{username:u,password:p}});
    if (res.error) { showMsg(msg, res.error, 'error'); return; }
    state.token = res.token; state.username = res.username;
    localStorage.setItem('pm_token', res.token);
    localStorage.setItem('pm_user',  res.username);
    showMachinesPage();
  });

  document.getElementById('btn-register').addEventListener('click', async () => {
    const u = document.getElementById('reg-user').value.trim();
    const p = document.getElementById('reg-pass').value;
    const msg = document.getElementById('reg-msg');
    if (!u || !p) { showMsg(msg, 'Username and password required', 'error'); return; }
    if (p.length < 12 || p.length > 128) { showMsg(msg, 'Password must be 12-128 characters', 'error'); return; }
    const res = await api('/api/register', {method:'POST', body:{username:u,password:p}});
    if (res.error) { showMsg(msg, res.error, 'error'); return; }
    showMsg(msg, 'Account created! Sign in now.', 'success');
  });

  ['login-user','login-pass'].forEach(id => {
    document.getElementById(id)?.addEventListener('keydown', e => {
      if (e.key === 'Enter') document.getElementById('btn-login').click();
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MACHINES PAGE WIRING
// ═══════════════════════════════════════════════════════════════════════════════
function wireMachinesPage() {
  document.getElementById('btn-logout-m').addEventListener('click', doLogout);
  document.getElementById('theme-toggle-m').addEventListener('click', toggleTheme);
  document.getElementById('btn-add-machine').addEventListener('click', addMachine);

  // "This Machine" — monitor the server host; IP resolved at runtime via API
  document.getElementById('btn-this-machine').addEventListener('click', () => {
    const ip       = state.localHost?.ip       || '127.0.0.1';
    const hostname = state.localHost?.hostname || 'This Machine';
    showMonitorPage({ name: hostname, host: ip, ephemeral: true });
  });

  // Quick scan — any arbitrary host, not saved
  document.getElementById('btn-quick-scan').addEventListener('click', () => {
    const host = document.getElementById('qs-host').value.trim();
    const msg  = document.getElementById('qs-msg');
    if (!host) { showMsg(msg, 'Enter a host or IP address', 'error'); return; }
    showMonitorPage({ name: 'Quick Scan', host, ephemeral: true });
  });
  document.getElementById('qs-host').addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('btn-quick-scan').click();
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MONITOR PAGE WIRING
// ═══════════════════════════════════════════════════════════════════════════════
function wireMonitorPage() {
  // Tab nav
  document.querySelectorAll('#page-monitor .nav-btn').forEach(btn =>
    btn.addEventListener('click', () => switchMonitorTab(btn.dataset.tab)));

  // Top-bar buttons
  document.getElementById('btn-back').addEventListener('click', () => {
    stopAllScans();
    showMachinesPage();
  });
  document.getElementById('btn-logout-mon').addEventListener('click', doLogout);
  document.getElementById('theme-toggle-mon').addEventListener('click', toggleTheme);
  document.getElementById('btn-export').addEventListener('click', exportReport);

  // TCP filters + sort
  ['tcp-search','tcp-filter-status','tcp-filter-risk'].forEach(id => {
    document.getElementById(id)?.addEventListener('input',  () => applyFilters('tcp'));
    document.getElementById(id)?.addEventListener('change', () => applyFilters('tcp'));
  });
  document.querySelectorAll('#tcp-table th[data-col]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.col;
      if (state.tcp.sortKey === col) state.tcp.sortDir = state.tcp.sortDir === 'asc' ? 'desc' : 'asc';
      else { state.tcp.sortKey = col; state.tcp.sortDir = 'asc'; }
      updateSortHeaders('tcp');
      applyFilters('tcp');
    });
  });

  // UDP filters + sort
  ['udp-search','udp-filter-status','udp-filter-risk'].forEach(id => {
    document.getElementById(id)?.addEventListener('input',  () => applyFilters('udp'));
    document.getElementById(id)?.addEventListener('change', () => applyFilters('udp'));
  });
  document.querySelectorAll('#udp-table th[data-col]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.col;
      if (state.udp.sortKey === col) state.udp.sortDir = state.udp.sortDir === 'asc' ? 'desc' : 'asc';
      else { state.udp.sortKey = col; state.udp.sortDir = 'asc'; }
      updateSortHeaders('udp');
      applyFilters('udp');
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CONTINUOUS LIVE SCAN ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

function startScan(proto) {
  const scan = state[proto];
  if (scan.running) return;

  const host    = state.activeMachine.host;
  const start   = Number(document.getElementById('scan-start').value);
  const end     = Number(document.getElementById('scan-end').value);
  const timeout = Number(document.getElementById('scan-timeout').value);
  const label   = document.getElementById('live-label');
  if (!Number.isInteger(start) || !Number.isInteger(end) ||
      start < 1 || end > 65535 || start > end || timeout < 0.1 || timeout > 3) {
    if (label) label.textContent = 'Invalid scan settings: ports must be 1-65535 and timeout 0.1-3 seconds.';
    return;
  }

  // Keep existing results map so we can merge updates (don't wipe on new cycle)
  if (!scan.map) scan.map = {};   // port → result object, persists across cycles
  scan.running = true;
  scan.autoReconnect = true;

  const wsPath  = proto === 'tcp' ? '/ws/scan' : '/ws/scan_udp';
  const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws      = new WebSocket(`${wsProto}//${location.host}${wsPath}`);
  scan.ws       = ws;

  const initMsg = { token: state.token, host, timeout, start, end,
                    batch: proto === 'udp' ? 100 : 500 };
  ws.onopen = () => ws.send(JSON.stringify(initMsg));

  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);

    if (msg.type === 'start') {
      setLiveStatus(proto, 'scanning', msg.total);

    } else if (msg.type === 'cycle_start') {
      // New sweep starting — reset progress but keep existing results visible
      scan.cycleTotal   = msg.total;
      scan.cycleScanned = 0;
      setLiveLabel(`TCP sweep ${msg.cycle}…`, `UDP sweep ${msg.cycle}…`, proto);
      setProgress(0, msg.total);

    } else if (msg.type === 'batch') {
      // Merge into map: update existing ports, add new ones
      msg.results.forEach(r => { scan.map[r.port] = r; });
      // Rebuild flat array from map for rendering
      scan.results = Object.values(scan.map);
      scan.cycleScanned = (scan.cycleScanned || 0) + msg.results.length;
      setProgress(scan.cycleScanned, scan.cycleTotal || msg.total);
      applyFilters(proto, true);
      // Throttle dashboard refresh — only update every 3s during streaming
      // to avoid 130 chart redraws per sweep causing lag
      throttleDashboard();

    } else if (msg.type === 'cycle_done') {
      scan.cycle = msg.cycle;
      setLiveSweep(proto, msg.cycle, msg.timestamp, msg.last_refreshed);
      setProgress(msg.total, msg.total);
      applyFilters(proto);       // full re-render after each complete sweep
      refreshDashboard();

    } else if (msg.type === 'error' || msg.error) {
      scan.autoReconnect = false;
      scan.running = false;
      setLiveLabel(`${proto.toUpperCase()} scan rejected: ${msg.error || 'unknown error'}`, `${proto.toUpperCase()} scan rejected: ${msg.error || 'unknown error'}`, proto);
      ws.close();
    }
  };

  ws.onerror = () => setLiveLabel('TCP connection interrupted…', 'UDP connection interrupted…', proto);
  ws.onclose = () => {
    if (scan.ws !== ws) return;
    scan.running = false;
    scan.ws = null;
    // Only auto-reconnect if we're still on the monitor page and haven't navigated away
    if (scan.autoReconnect && state.activeMachine) reconnectScan(proto, 2000);
  };
}

// Reconnect after `delayMs` — used when the WS closes unexpectedly
function reconnectScan(proto, delayMs) {
  const scan = state[proto];
  scan.running = false;
  scan.ws = null;
  if (!state.activeMachine) return;   // user navigated away
  setLiveLabel('Reconnecting TCP…', 'Reconnecting UDP…', proto);
  setTimeout(() => {
    if (state.activeMachine) startScan(proto);
  }, delayMs);
}

function stopAllScans() {
  state.activeMachine = null;   // signal reconnect guard to not re-connect
  ['tcp','udp'].forEach(p => {
    if (state[p].ws) { state[p].ws.close(); state[p].ws = null; }
    state[p].running = false;
    state[p].autoReconnect = false;
    state[p].map = {};
  });
}

// Manual refresh — restart both scans immediately from scratch
function manualRefresh() {
  if (!state.activeMachine) return;
  const machine = state.activeMachine;
  // Close existing websockets without clearing activeMachine
  ['tcp','udp'].forEach(p => {
    if (state[p].ws) { state[p].ws.close(); state[p].ws = null; }
    state[p].running = false;
    state[p].autoReconnect = false;
    state[p].map = {};
    state[p].results = [];
  });
  // Reset UI
  const upd = document.getElementById('live-updated');
  if (upd) upd.textContent = 'Refreshing…';
  const lbl = document.getElementById('live-label');
  if (lbl) lbl.textContent = 'Restarting scan…';
  setProgress(0, 0);
  // Restart both scans
  startScan('tcp');
  startScan('udp');
}

function setLiveStatus(proto, status, total) {
  const dot = document.getElementById('live-dot');
  if (dot) {
    dot.className = status === 'scanning' ? 'live-dot pulse' : 'live-dot';
  }
}

function setLiveLabel(tcpText, udpText, proto) {
  const label = document.getElementById('live-label');
  if (label) label.textContent = proto === 'tcp' ? tcpText : udpText;
}

function setLiveSweep(proto, cycle, isoTs, lastRefreshed) {
  const el = document.getElementById('live-sweep');
  const tcpCycle = proto === 'tcp' ? cycle : (state.tcp.cycle || 0);
  const udpCycle = proto === 'udp' ? cycle : (state.udp.cycle || 0);
  if (el) el.textContent = `TCP sweep ${tcpCycle}  ·  UDP sweep ${udpCycle}`;

  const upd = document.getElementById('live-updated');
  if (upd) {
    // Prefer server-formatted time (time.strftime); fall back to parsing ISO timestamp
    if (lastRefreshed) {
      upd.textContent = `Last refreshed: ${lastRefreshed}`;
    } else if (isoTs) {
      const d = new Date(isoTs + (isoTs.endsWith('Z') ? '' : 'Z'));
      upd.textContent = `Last refreshed: ${d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'})}`;
    }
  }

  const dot = document.getElementById('live-dot');
  if (dot) dot.className = 'live-dot live-flash';
  setTimeout(() => {
    const d = document.getElementById('live-dot');
    if (d) d.className = 'live-dot pulse';
  }, 600);

  const lbl = document.getElementById('live-label');
  if (lbl) lbl.textContent = 'Live · monitoring selected port range';
}

function setProgress(done, total) {
  const pct = total > 0 ? Math.round(done * 100 / total) : 0;
  const bar = document.getElementById('progress-bar');
  const txt = document.getElementById('progress-txt');
  if (bar) bar.style.width = pct + '%';
  if (txt) txt.textContent = `${pct}%`;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FILTER / SORT / RENDER
// ═══════════════════════════════════════════════════════════════════════════════
const RISK_ORDER = { critical:0, high:1, medium:2, low:3, none:4 };

function applyFilters(proto, streaming = false) {
  const scan = state[proto];

  const searchEl  = document.getElementById(`${proto}-search`);
  const statusEl  = document.getElementById(`${proto}-filter-status`);
  const riskEl    = document.getElementById(`${proto}-filter-risk`);

  const search  = (searchEl?.value  || '').toLowerCase();
  const fStatus = statusEl?.value   || 'all';
  const fRisk   = riskEl?.value     || 'all';
  let rows = scan.results.slice();
  if (fStatus !== 'all') rows = rows.filter(r => r.status === fStatus);
  if (fRisk   !== 'all') rows = rows.filter(r => r.risk   === fRisk);
  if (search) rows = rows.filter(r =>
    String(r.port).includes(search)              ||
    (r.service || '').toLowerCase().includes(search) ||
    (r.status  || '').toLowerCase().includes(search) ||
    (r.risk    || '').toLowerCase().includes(search) ||
    (r.banner  || '').toLowerCase().includes(search)
  );

  rows.sort((a, b) => {
    const key = scan.sortKey;
    let av = a[key], bv = b[key];
    if (key === 'risk')    { av = RISK_ORDER[av] ?? 9; bv = RISK_ORDER[bv] ?? 9; }
    const dir = scan.sortDir === 'asc' ? 1 : -1;
    if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
    return String(av).localeCompare(String(bv)) * dir;
  });

  renderTable(proto, rows, streaming);
}

function renderTable(proto, rows, streaming = false) {
  const tbody = document.getElementById(`${proto}-tbody`);
  const count = document.getElementById(`${proto}-count`);
  const open  = rows.filter(r => r.status === 'open').length;
  const filtered = rows.filter(r => r.status === 'filtered').length;
  const uncertain = rows.filter(r => r.status === 'open|filtered').length;
  count.textContent = `${rows.length.toLocaleString()} ports · ${open} open · ${filtered} filtered · ${uncertain} open|filtered`;

  if (!rows.length) {
    const emptyMsg = state[proto].results.length ? 'No ports match filters' : `Click ▶ Scan ${proto.toUpperCase()} to start`;
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state"><div class="icon">🔍</div><div>${emptyMsg}</div></td></tr>`;
    return;
  }

  // During streaming cap at 3000 rows for performance; show all after done
  const display = streaming ? rows.slice(0, 3000) : rows;

  tbody.innerHTML = display.map(r => {
    const sc       = r.status === 'open' ? 'open'
      : (r.status === 'filtered' || r.status === 'open|filtered') ? 'filtered' : 'closed';
    const rc       = r.risk === 'none' ? 'none' : r.risk;
    const dot      = r.status === 'open' ? 'green'
      : (r.status === 'filtered' || r.status === 'open|filtered') ? 'yellow' : 'red';
    const exp      = '<span class="badge badge-outline">Not measured</span>';
    const note     = r.banner ? escHtml(r.banner) : (vulnNote(r.port) || '');
    return `<tr>
      <td><strong>${r.port}</strong></td>
      <td>${escHtml(r.service || '—')}</td>
      <td><span class="dot dot-${dot}"></span><span class="badge badge-${sc}">${r.status}</span></td>
      <td><span class="badge badge-${rc}">${r.risk}</span></td>
      <td>${exp}</td>
      <td class="text-muted text-sm note-cell">${note}</td>
    </tr>`;
  }).join('');

  if (streaming && rows.length > 3000) {
    tbody.innerHTML += `<tr><td colspan="6" class="text-muted text-sm" style="padding:.5rem 1rem">
      … ${(rows.length - 3000).toLocaleString()} more rows — scroll after scan completes
    </td></tr>`;
  }
}

function updateSortHeaders(proto) {
  const scan = state[proto];
  document.querySelectorAll(`#${proto}-table th[data-col]`).forEach(th => {
    th.classList.toggle('sorted', th.dataset.col === scan.sortKey);
    const arrow = th.querySelector('.sort-arrow');
    if (arrow) arrow.textContent =
      th.dataset.col === scan.sortKey ? (scan.sortDir === 'asc' ? '▲' : '▼') : '↕';
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════════

// Throttle: call refreshDashboard at most once every 3 seconds during streaming
let _dashTimer = null;
function throttleDashboard() {
  if (_dashTimer) return;
  _dashTimer = setTimeout(() => {
    _dashTimer = null;
    if (document.getElementById('tab-dashboard').classList.contains('active')) {
      refreshDashboard();
    }
  }, 3000);
}

function refreshDashboard() {
  const tcp       = state.tcp.results;
  const udp       = state.udp.results;
  const tcpOpen   = tcp.filter(r => r.status === 'open');
  const tcpClosed = tcp.filter(r => r.status === 'closed');
  const tcpFiltered = tcp.filter(r => r.status === 'filtered');
  const udpOpen   = udp.filter(r => r.status === 'open' || r.status === 'open|filtered');
  const udpClosed = udp.filter(r => r.status === 'closed');
  const critical  = [...tcpOpen, ...udpOpen].filter(r => r.risk === 'critical');

  setStatVal('stat-open',     tcpOpen.length   || '—');
  setStatVal('stat-closed',   tcpClosed.length || '—');
  setStatVal('stat-tcp-filtered', tcpFiltered.length || '—');
  setStatVal('stat-exposed', 'Not measured');
  setStatVal('stat-critical', critical.length  || '—');
  setStatVal('stat-udp',      udpOpen.length   || '—');
  setStatVal('stat-udp-closed', udpClosed.length || '—');

  if (!state.charts.status) return;

  // Status pie — only render if both values are non-zero to avoid invisible slices
  const pieOpen   = tcpOpen.length;
  const pieClosed = tcpClosed.length;
  state.charts.status.data.datasets[0].data = pieOpen || pieClosed || tcpFiltered.length
    ? [pieOpen, pieClosed, tcpFiltered.length]
    : [0, 1, 0];
  state.charts.status.update('none');  // 'none' = skip animation → no lag

  // UDP status pie
  if (state.charts.udpStatus) {
    state.charts.udpStatus.data.datasets[0].data = udpOpen.length || udpClosed.length
      ? [udpOpen.length, udpClosed.length]
      : [0, 1];
    state.charts.udpStatus.update('none');
  }

  // Risk pie (TCP + UDP combined)
  const rc = { critical:0, high:0, medium:0, low:0 };
  [...tcpOpen, ...udpOpen].forEach(r => { if (rc[r.risk] !== undefined) rc[r.risk]++; });
  state.charts.risk.data.datasets[0].data = Object.values(rc);
  state.charts.risk.update('none');

  // Top services (TCP + UDP combined)
  const svcMap = {};
  [...tcpOpen, ...udpOpen].forEach(r => {
    if (r.service && r.service !== '—' && r.service !== 'unknown' && r.service !== '-')
      svcMap[r.service] = (svcMap[r.service] || 0) + 1;
  });
  const top = Object.entries(svcMap).sort((a,b) => b[1]-a[1]).slice(0,10);
  state.charts.services.data.labels               = top.map(e => e[0]);
  state.charts.services.data.datasets[0].data     = top.map(e => e[1]);
  state.charts.services.update('none');

  // Port range activity (TCP open)
  const bands = [0,0,0,0];
  tcpOpen.forEach(r => {
    if      (r.port <=  1023) bands[0]++;
    else if (r.port <=  9999) bands[1]++;
    else if (r.port <= 49151) bands[2]++;
    else                       bands[3]++;
  });
  state.charts.ranges.data.datasets[0].data = bands;
  state.charts.ranges.update('none');

  // Critical/High table
  const allOpen  = [...tcpOpen, ...udpOpen];
  const vulnPorts = allOpen.filter(r => r.risk === 'critical' || r.risk === 'high');
  const ctbody   = document.getElementById('critical-tbody');
  if (!vulnPorts.length) {
    const hasData = tcp.length || udp.length;
    ctbody.innerHTML = `<tr><td colspan="6" class="empty-state">${hasData ? 'No critical/high risk ports found 🎉' : 'Run a scan to see results'}</td></tr>`;
    return;
  }
  ctbody.innerHTML = vulnPorts.map(r => `<tr>
    <td><strong>${r.port}</strong></td>
    <td><span class="proto-badge proto-${r.proto}">${r.proto.toUpperCase()}</span></td>
    <td>${escHtml(r.service || '—')}</td>
    <td><span class="badge badge-${r.risk}">${r.risk}</span></td>
    <td><span class="badge badge-outline">Not measured</span></td>
    <td class="text-muted text-sm note-cell">${r.banner ? escHtml(r.banner) : (vulnNote(r.port)||'')}</td>
  </tr>`).join('');
}

function setStatVal(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// Static advisory notes for common risky ports (fallback when no live banner)
function vulnNote(port) {
  const notes = {
    23:    'Telnet – plaintext, no encryption',
    21:    'FTP – credentials sent in clear',
    445:   'SMB – WannaCry/EternalBlue vector',
    3389:  'RDP – brute-force target',
    5900:  'VNC – often misconfigured',
    4444:  'Metasploit default listener',
    2375:  'Docker daemon – unencrypted API',
    11211: 'Memcached – amplification attack risk',
    27017: 'MongoDB – often no auth by default',
    9200:  'Elasticsearch – unauthenticated by default',
    6379:  'Redis – no auth by default',
    22:    'SSH – keep updated, disable password auth',
    80:    'HTTP – unencrypted web traffic',
    8080:  'HTTP-alt – dev servers sometimes exposed',
    3306:  'MySQL – DB on public interface',
    5432:  'PostgreSQL – DB on public interface',
    1433:  'MSSQL – DB on public interface',
  };
  return notes[port] || '';
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CHARTS
// ═══════════════════════════════════════════════════════════════════════════════
function getChartDefaults() {
  const isDark = document.body.classList.contains('dark');
  return {
    gridColor:  isDark ? 'rgba(255,255,255,.06)' : 'rgba(0,0,0,.06)',
    textColor:  isDark ? '#8b949e' : '#636c76',
    tooltipBg:  isDark ? '#1c2333' : '#ffffff',
  };
}

function initCharts() {
  const d = getChartDefaults();
  const pieOpts = (labels, data, colors) => ({
    type: 'doughnut',
    data: { labels, datasets:[{ data, backgroundColor:colors, borderWidth:1, borderColor:'transparent', hoverOffset:4 }] },
    options: {
      responsive:true, maintainAspectRatio:false, cutout:'60%',
      plugins:{
        legend:{ position:'right', labels:{ color:d.textColor, font:{size:11}, boxWidth:12 } },
        tooltip:{ backgroundColor:d.tooltipBg, titleColor:d.textColor, bodyColor:d.textColor, borderColor:'#30363d', borderWidth:1 },
      },
    }
  });
  const barOpts = (labels, data, color, label) => ({
    type: 'bar',
    data: { labels, datasets:[{ label, data, backgroundColor:color+'aa', borderColor:color, borderWidth:1, borderRadius:4 }] },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{
        legend:{ display:false },
        tooltip:{ backgroundColor:d.tooltipBg, titleColor:d.textColor, bodyColor:d.textColor },
      },
      scales:{
        x:{ grid:{ color:d.gridColor }, ticks:{ color:d.textColor, font:{size:10} } },
        y:{ grid:{ color:d.gridColor }, ticks:{ color:d.textColor, font:{size:10} }, beginAtZero:true },
      }
    }
  });

  state.charts.status    = new Chart(document.getElementById('chart-status'),
    pieOpts(['Open','Closed','Filtered'],[0,1,0],['#3fb950','#30363d','#d29922']));
  state.charts.udpStatus = new Chart(document.getElementById('chart-udp-status'),
    pieOpts(['Open/Filtered','Closed'],[0,1],['#58a6ff','#30363d']));
  state.charts.risk      = new Chart(document.getElementById('chart-risk'),
    pieOpts(['Critical','High','Medium','Low'],[0,0,0,0],['#ff4444','#d29922','#bc8cff','#3fb950']));
  state.charts.services  = new Chart(document.getElementById('chart-services'),
    barOpts(['—'],[0],'#58a6ff','Ports'));
  state.charts.ranges    = new Chart(document.getElementById('chart-ranges'),
    barOpts(['1–1023','1024–9999','10000–49151','49152–65535'],[0,0,0,0],'#bc8cff','Open TCP'));
}

function destroyCharts() {
  Object.values(state.charts).forEach(c => c && c.destroy());
  state.charts = {};
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MACHINES MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════
async function loadLocalHost() {
  const data = await api('/api/local-host');
  if (!data.error) {
    state.localHost = data;
    const label = document.getElementById('tm-host-label');
    if (label) label.textContent = `${data.hostname}  ·  ${data.ip}`;
    // Show OS badge on the "This Machine" card
    const osBadge = document.getElementById('tm-os-badge');
    if (osBadge && data.os) {
      osBadge.textContent = data.os + (data.version ? ' ' + data.version : '');
      osBadge.style.display = '';
    }
  } else showMsg(document.getElementById('tm-host-label'), data.error, 'error');
}

async function loadMachines() {
  const data = await api('/api/machines');
  if (!data.error) {
    state.machines = data;
    renderMachines();
  } else showMsg(document.getElementById('machines-grid'), data.error, 'error');
}

// Fetch OS for a machine, cache on the object, update the badge in the grid
async function fetchAndCacheOS(machine, callback) {
  const data = await api(`/api/os-detect?host=${encodeURIComponent(machine.host)}`);
  if (data && !data.error && data.os && data.os !== 'Unknown') {
    machine.os         = data.os;
    machine.os_version = data.version || '';
    // Update the "Detecting…" badge in the machines grid if still visible
    const badge = document.getElementById(`os-badge-${machine.id}`);
    if (badge) {
      badge.textContent = machine.os + (machine.os_version ? ' ' + machine.os_version : '');
      badge.classList.remove('os-badge-detecting');
    }
    if (callback) callback(machine.os, machine.os_version);
  } else {
    machine.os         = 'Unknown';
    machine.os_version = '';
    const badge = document.getElementById(`os-badge-${machine.id}`);
    if (badge) { badge.textContent = 'Unknown'; badge.classList.remove('os-badge-detecting'); }
    if (callback) callback('Unknown', '');
  }
}

async function addMachine() {
  const name = document.getElementById('mc-name').value.trim();
  const host = document.getElementById('mc-host').value.trim();
  const msg  = document.getElementById('mc-msg');
  if (!name || !host) { showMsg(msg, 'Name and host required', 'error'); return; }
  const res = await api('/api/machines', {method:'POST', body:{name,host}});
  if (res.error) { showMsg(msg, res.error, 'error'); return; }
  showMsg(msg, 'Machine added!', 'success');
  document.getElementById('mc-name').value = '';
  document.getElementById('mc-host').value = '';
  await loadMachines();
}

async function deleteMachine(id) {
  if (!confirm('Remove this machine?')) return;
  await api(`/api/machines/${id}`, {method:'DELETE'});
  await loadMachines();
}

function renderMachines() {
  const grid = document.getElementById('machines-grid');
  if (!state.machines.length) {
    grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1"><div class="icon">🖥</div><div>No machines saved yet — add one below or use Quick Scan above.</div></div>';
    return;
  }
  grid.innerHTML = state.machines.map(m => `
    <div class="machine-card" onclick="openMachine('${m.id}')">
      <div class="mc-icon">${iconRadar(24)}</div>
      <div class="mc-info">
        <div class="mc-name">${escHtml(m.name)}</div>
        <div class="mc-host">${escHtml(m.host)}</div>
        <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-top:.2rem">
          ${m.os ? `<span class="os-badge">${escHtml(m.os)}${m.os_version ? ' ' + escHtml(m.os_version) : ''}</span>` : `<span class="os-badge os-badge-detecting" id="os-badge-${m.id}">Detecting…</span>`}
          <span class="mc-meta">${m.last_scan ? 'Last scan: ' + formatDate(m.last_scan) : 'Never scanned'}</span>
        </div>
      </div>
      <div class="mc-actions" onclick="event.stopPropagation()">
        <button class="btn btn-primary btn-sm" onclick="openMachine('${m.id}')">▶ Monitor</button>
        <button class="btn btn-danger btn-sm"  onclick="deleteMachine('${m.id}')">✕</button>
      </div>
    </div>
  `).join('');
  // Fetch OS for any machines that don't have it cached yet
  state.machines.forEach(m => {
    if (!m.os) fetchAndCacheOS(m);
  });
}

function openMachine(id) {
  const m = state.machines.find(x => x.id === id);
  if (m) showMonitorPage(m);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EXPORT
// ═══════════════════════════════════════════════════════════════════════════════
function exportReport() {
  const tcp = state.tcp.results;
  const udp = state.udp.results;
  if (!tcp.length && !udp.length) { alert('No scan data to export. Run a scan first.'); return; }

  const host = state.activeMachine?.host || 'unknown';
  const ts   = new Date().toISOString();
  const csvCell = value => {
    let text = String(value ?? '');
    if (/^[\s]*[=+\-@]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  };
  const lines = [
    ['host', 'scanned_at', 'port', 'protocol', 'service', 'status', 'risk', 'internet_exposure', 'banner'].map(csvCell).join(','),
    ...[...tcp, ...udp].map(r => [
      host, ts, r.port, r.proto, r.service, r.status, r.risk, 'not measured', r.banner || ''
    ].map(csvCell).join(',')),
  ];

  const blob = new Blob([lines.join('\n')], {type:'text/csv'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `portmonitor-${host.replace(/[^A-Za-z0-9_.-]/g, '_')}-${ts.slice(0,10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  THEME
// ═══════════════════════════════════════════════════════════════════════════════
function toggleTheme() {
  state.theme = state.theme === 'dark' ? 'light' : 'dark';
  document.body.className = state.theme;
  localStorage.setItem('pm_theme', state.theme);
  updateThemeBtns();
  destroyCharts();
  initCharts();
  refreshDashboard();
}

function updateThemeBtns() {
  const label = state.theme === 'dark' ? '☀ Light' : '🌙 Dark';
  ['theme-toggle-m','theme-toggle-mon'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = label;
  });
}

// ─── Logout ───────────────────────────────────────────────────────────────────
async function doLogout() {
  stopAllScans();
  const result = await api('/api/logout', {method:'POST'});
  if (result.error) console.error('Logout request failed:', result.error);
  state.token = null; state.username = null;
  localStorage.removeItem('pm_token');
  localStorage.removeItem('pm_user');
  showAuthPage();
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
async function api(url, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.token) headers['X-Token'] = state.token;
  let res;
  try {
    res = await fetch(url, {
      method:  opts.method || 'GET',
      headers,
      body:    opts.body ? JSON.stringify(opts.body) : undefined,
    });
  } catch (e) {
    if (e instanceof TypeError) return { error: `Network request failed: ${e.message}` };
    throw e;
  }
  const payload = await res.json();
  if (res.status === 401) {
    state.token = null;
    state.username = null;
    localStorage.removeItem('pm_token');
    localStorage.removeItem('pm_user');
    showAuthPage();
  }
  if (!res.ok) return { ...payload, error: payload.error || `Request failed (${res.status})` };
  return payload;
}

function showMsg(el, text, type) {
  const message = document.createElement('div');
  message.className = `msg ${type}`;
  message.textContent = text;
  el.replaceChildren(message);
  setTimeout(() => { if (el.contains(message)) el.replaceChildren(); }, 4000);
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatDate(iso) {
  if (!iso) return '';
  const d = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'));
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
}

// Expose for inline onclick
window.deleteMachine = deleteMachine;
window.openMachine   = openMachine;
