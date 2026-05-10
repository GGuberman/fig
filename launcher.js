(function(){
'use strict';

// fig-shared.js must be loaded first (provides FIG_PROVIDERS, figGetConfig, figSetConfig, etc.)

// ── CSS injection ─────────────────────────────
function injectStyles() {
  var style = document.createElement('style');
  style.textContent = `
.fig-overlay{position:fixed;inset:0;background:#0a0a0f;z-index:10000;display:flex;align-items:center;justify-content:center;padding:20px;opacity:0;transition:opacity 0.25s;pointer-events:none}
.fig-overlay.open{opacity:1;pointer-events:auto}
.fig-launcher{background:var(--surface,#12121a);border:1px solid var(--border,#252535);border-radius:18px;padding:36px 32px 28px;width:480px;max-width:100%;max-height:90vh;overflow-y:auto;position:relative;transform:translateY(8px);transition:transform 0.25s}
.fig-overlay.open .fig-launcher{transform:translateY(0)}
.fig-close{position:absolute;top:14px;right:16px;background:none;border:none;color:var(--muted,#6b6880);font-size:18px;cursor:pointer;padding:4px 8px;font-family:inherit;line-height:1}
.fig-wordmark{font-family:'Fraunces',serif;font-size:1.5rem;color:var(--accent2,#c4aaff);margin-bottom:2px;letter-spacing:-0.02em}
.fig-wordmark-tag{font-size:0.58rem;letter-spacing:0.18em;text-transform:uppercase;color:var(--muted,#6b6880)}
.fig-step-indicator{display:flex;gap:6px;margin-bottom:28px}
.fig-dot{width:8px;height:8px;border-radius:50%;background:var(--border,#252535);transition:all 0.3s}
.fig-dot.active{background:var(--accent,#9b7fe8);width:24px;border-radius:4px}
.fig-dot.done{background:var(--accent-mid,#9b7fe844)}
.fig-step-content{min-height:280px;display:flex;flex-direction:column}
.fig-h1{font-family:'Fraunces',serif;font-size:1.3rem;color:var(--text,#e8e4f0);margin-bottom:8px;line-height:1.3}
.fig-h2{font-family:'Fraunces',serif;font-size:1.1rem;color:var(--text,#e8e4f0);margin-bottom:6px}
.fig-desc{font-size:0.72rem;color:var(--muted,#6b6880);line-height:1.7;margin-bottom:24px}
.fig-desc a{color:var(--accent2,#c4aaff);text-decoration:none}
.fig-desc a:hover{text-decoration:underline}
.fig-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:20px}
.fig-card{padding:14px;border:1px solid var(--border,#252535);border-radius:10px;cursor:pointer;transition:all 0.15s;background:transparent;text-align:left;font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;color:var(--text,#e8e4f0)}
.fig-card:hover{border-color:var(--accent,#9b7fe8);background:rgba(155,127,232,0.04)}
.fig-card.selected{border-color:var(--accent,#9b7fe8);background:rgba(155,127,232,0.08)}
.fig-card-icon{font-size:1.3rem;margin-bottom:6px;display:block}
.fig-card-name{font-family:'Fraunces',serif;font-size:0.85rem;color:var(--text,#e8e4f0);margin-bottom:2px}
.fig-card.selected .fig-card-name{color:var(--accent2,#c4aaff)}
.fig-card-desc{font-size:0.6rem;color:var(--muted,#6b6880);line-height:1.5}
.fig-btn-row{display:flex;gap:10px;margin-top:auto;padding-top:24px;align-items:center}
.fig-btn-row .fig-spacer{flex:1}
.fig-btn{padding:10px 24px;border-radius:8px;border:none;cursor:pointer;font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;font-size:0.72rem;letter-spacing:0.08em;text-transform:uppercase;transition:opacity 0.15s;font-weight:500}
.fig-btn:hover{opacity:0.85}
.fig-btn.primary{background:var(--accent,#9b7fe8);color:var(--bg,#0a0a0f)}
.fig-btn.secondary{background:transparent;border:1px solid var(--border,#252535);color:var(--muted,#6b6880)}
.fig-btn.ghost{background:transparent;border:none;color:var(--muted,#6b6880);padding:10px 8px}
.fig-btn.ghost:hover{color:var(--text,#e8e4f0);opacity:1}
.fig-btn.danger{background:transparent;border:1px solid var(--red,#e07070);color:var(--red,#e07070)}
.fig-btn:disabled{opacity:0.4;cursor:not-allowed}
.fig-field{margin-bottom:14px}
.fig-field label{display:block;font-size:0.6rem;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted,#6b6880);margin-bottom:5px}
.fig-field input{width:100%;background:var(--surface2,#1a1a26);border:1px solid var(--border,#252535);border-radius:8px;padding:10px 12px;color:var(--text,#e8e4f0);font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;font-size:0.78rem;outline:none;transition:border-color 0.15s}
.fig-field input:focus{border-color:var(--accent,#9b7fe8)}
.fig-field .fig-field-help{font-size:0.6rem;color:var(--muted,#6b6880);margin-top:4px;line-height:1.5}
.fig-field .fig-field-help a{color:var(--accent2,#c4aaff);text-decoration:none}
.fig-status{display:flex;align-items:center;gap:8px;font-size:0.68rem;color:var(--muted,#6b6880);margin-bottom:16px;padding:10px 14px;background:var(--surface2,#1a1a26);border-radius:8px}
.fig-status.connected{color:var(--green,#7ec8a0);border:1px solid var(--green,#7ec8a0)}
.fig-status .fig-dot-online{width:6px;height:6px;border-radius:50%;background:var(--green,#7ec8a0);flex-shrink:0}
.fig-toast{font-size:0.62rem;min-height:1.2em;color:var(--muted,#6b6880)}
.fig-toast.ok{color:var(--green,#7ec8a0)}
.fig-toast.err{color:var(--red,#e07070)}
.fig-welcome-icon{font-size:2.2rem;margin-bottom:12px;display:block}
.fig-done-grid{display:flex;flex-direction:column;gap:8px;margin-bottom:20px}
.fig-done-item{display:flex;align-items:center;gap:10px;padding:12px 14px;background:var(--surface2,#1a1a26);border:1px solid var(--border,#252535);border-radius:8px;font-size:0.75rem;color:var(--text,#e8e4f0)}
.fig-done-item .fig-done-icon{width:20px;text-align:center;font-size:0.9rem}
.fig-done-item.done{opacity:1}
.fig-done-item.skipped{opacity:0.5}
.fig-sentry{position:fixed;top:12px;left:12px;z-index:9999;display:flex;gap:6px;align-items:center}
.fig-sentry-btn{background:var(--surface,#12121a);border:1px solid var(--border,#252535);border-radius:6px;padding:5px 9px;color:var(--muted,#6b6880);font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;font-size:0.6rem;letter-spacing:0.06em;text-transform:uppercase;cursor:pointer;text-decoration:none;transition:all 0.15s;line-height:1;display:flex;align-items:center;gap:4px}
.fig-sentry-btn:hover{border-color:var(--accent,#9b7fe8);color:var(--accent2,#c4aaff)}
.fig-sentry-btn .fig-dot-online{width:5px;height:5px;border-radius:50%;background:var(--border,#252535);flex-shrink:0}
.fig-sentry-btn .fig-dot-online.wid{background:var(--green,#7ec8a0)}
.fig-sentry-btn .fig-dot-online.llm{background:var(--accent,#9b7fe8)}
@media(max-width:520px){.fig-launcher{padding:28px 20px 24px}.fig-grid{grid-template-columns:1fr}}
`;
  document.head.appendChild(style);
}

// ── Render helper ─────────────────────────────
var _step = 0;
var _launcherEl = null;
var _overlayEl = null;
var _isSettings = false; // true when re-opened from gear

function renderDots() {
  var total = _isSettings ? 2 : 4;
  var dots = '';
  for (var i = 0; i < total; i++) {
    var cls = 'fig-dot';
    if (i < _step) cls += ' done';
    else if (i === _step) cls += ' active';
    dots += '<span class="' + cls + '"></span>';
  }
  return '<div class="fig-step-indicator">' + dots + '</div>';
}

function render() {
  if (!_launcherEl) return;
  var html = '';
  if (_isSettings) {
    if (_step === 0) html = figRenderIdentity();
    else if (_step === 1) html = figRenderLLM();
  } else {
    if (_step === 0) html = figRenderAccount();
    else if (_step === 1) html = figRenderIdentity();
    else if (_step === 2) html = figRenderLLM();
    else if (_step === 3) html = figRenderDone();
  }
  _launcherEl.innerHTML = renderDots() + '<div class="fig-step-content">' + html + '</div>';
}

function nextStep() {
  var total = _isSettings ? 2 : 4;
  if (_step < total - 1) { _step++; render(); }
}

function prevStep() {
  if (_step > 0) { _step--; render(); }
}

// ── Account step ──────────────────────────────
function figRenderAccount() {
  var cfg = figGetConfig();
  var ident = cfg.identity || {};
  var session = figGetSession();
  var emailConnected = session && session.email;
  var workerConnected = ident.worker && ident.worker.handle && ident.worker.token;

  if (emailConnected || workerConnected) {
    var label = emailConnected ? session.email : ('@' + ident.worker.handle);
    return `
      <span style="font-size:1.5rem;margin-bottom:6px;display:block">👤</span>
      <div class="fig-h1">Your account</div>
      <div class="fig-status connected"><span class="fig-dot-online"></span> Signed in as <b>${label}</b></div>
      <div class="fig-desc">Your account is connected. You can manage it in Settings or proceed to set up identity and LLM.</div>
      <div class="fig-btn-row">
        <button class="fig-btn ghost" onclick="figDismissLauncher()">Skip setup</button>
        <span class="fig-spacer"></span>
        <button class="fig-btn primary" onclick="nextStep()">Next →</button>
      </div>`;
  }

  return `
    <span style="font-size:1.5rem;margin-bottom:6px;display:block">👤</span>
    <div class="fig-h1">Create your account</div>
    <div class="fig-desc">Sign in with email to save your data and sync across devices. Everything stays encrypted on your device.</div>
    <div class="fig-field">
      <label>Email</label>
      <input id="fig-acc-email" type="email" placeholder="you@example.com" autocomplete="email" onkeydown="if(event.key==='Enter')document.getElementById('fig-acc-pass').focus()">
    </div>
    <div class="fig-field">
      <label>Password</label>
      <input id="fig-acc-pass" type="password" placeholder="Choose a password" autocomplete="new-password" onkeydown="if(event.key==='Enter')figCreateEmailAccount()">
    </div>
    <div class="fig-btn-row" style="padding-top:0">
      <button class="fig-btn primary" onclick="figCreateEmailAccount()" style="padding:8px 18px;font-size:0.68rem">Sign up / Sign in →</button>
      <span id="fig-acc-toast" class="fig-toast" style="min-height:0"></span>
    </div>
    <details style="margin-top:16px;font-size:0.72rem;color:var(--muted,#6b6880)" ontoggle="if(this.open)figRenderWorkerOption()">
      <summary style="cursor:pointer;color:var(--muted,#6b6880);font-size:0.65rem;letter-spacing:0.08em">Advanced: Fig Handle (needs Worker)</summary>
      <div id="fig-acc-worker-option" style="margin-top:12px"></div>
    </details>
    <div class="fig-btn-row">
      <button class="fig-btn ghost" onclick="figDismissLauncher()">Skip — just show me the app</button>
      <span class="fig-spacer"></span>
      <button class="fig-btn primary" onclick="nextStep()">Next →</button>
    </div>`;
}

function figGetSession() {
  try { return JSON.parse(localStorage.getItem('fig_session') || 'null'); } catch(e) { return null; }
}

function figSetSession(session) {
  try { localStorage.setItem('fig_session', JSON.stringify(session)); } catch(e) {}
}

function figClearSession() {
  try { localStorage.removeItem('fig_session'); } catch(e) {}
}

async function figCreateEmailAccount() {
  var email = document.getElementById('fig-acc-email').value.trim();
  var pass = document.getElementById('fig-acc-pass').value;
  var toast = document.getElementById('fig-acc-toast');
  if (!email || !pass) { toast.className = 'fig-toast err'; toast.textContent = 'Email and password required.'; return; }
  toast.className = 'fig-toast'; toast.textContent = 'Signing in…';
  try {
    var hash = await figSimpleHash(pass);
    var key = 'fig_login_' + email.toLowerCase();
    var existing = localStorage.getItem(key);
    if (existing) {
      var d = JSON.parse(existing);
      if (d.hash !== hash) { toast.className = 'fig-toast err'; toast.textContent = 'Wrong password.'; return; }
    } else {
      localStorage.setItem(key, JSON.stringify({ hash: hash, createdAt: new Date().toISOString() }));
    }
    var cfg = figGetConfig();
    if (!cfg.identity) cfg.identity = {};
    cfg.identity.email = { address: email.toLowerCase(), createdAt: existing ? JSON.parse(existing).createdAt : new Date().toISOString() };
    figSetConfig(cfg);
    figSetSession({ email: email.toLowerCase(), loggedInAt: new Date().toISOString() });
    toast.className = 'fig-toast ok';
    toast.textContent = existing ? '✓ Signed in' : '✓ Account created';
    setTimeout(function() { render(); }, 500);
  } catch(e) {
    toast.className = 'fig-toast err'; toast.textContent = 'Error: ' + (e.message || e);
  }
}

async function figSimpleHash(str) {
  try {
    var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('').slice(0, 32);
  } catch(e) {
    var h = 0;
    for (var i = 0; i < str.length; i++) { h = ((h << 5) - h) + str.charCodeAt(i); h |= 0; }
    return Math.abs(h).toString(16);
  }
}

function figCreateWorkerAccount() {
  var input = document.getElementById('fig-acc-worker-handle');
  if (!input) return;
  var handle = input.value.trim();
  if (!handle) { input.focus(); return; }
  if (!/^[a-zA-Z0-9_-]{2,32}$/.test(handle)) {
    alert('Invalid handle. Use letters, numbers, _ and - (2-32 chars).');
    return;
  }
  var sync = figGetSync();
  var workerUrl = sync && sync.workerUrl;
  if (!workerUrl) { alert('Worker URL not configured. Set it in Settings → Cloud sync first.'); return; }
  var toast = document.getElementById('fig-acc-toast');
  if (toast) { toast.className = 'fig-toast'; toast.textContent = 'Creating…'; }
  var btn = document.querySelector('#fig-acc-toast') && document.querySelector('#fig-acc-toast').previousElementSibling;
  if (btn) btn.disabled = true;
  fetch(workerUrl.replace(/\/$/, '') + '/auth/register', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: handle })
  }).then(function(r) { return r.json().then(function(d) { return { ok: r.ok, status: r.status, data: d }; }); })
  .then(function(res) {
    if (!res.ok) {
      if (res.status === 409) { alert('Handle taken. Try another.'); if (btn) btn.disabled = false; return; }
      throw new Error(res.data.error || ('HTTP ' + res.status));
    }
    var cfg = figGetConfig();
    if (!cfg.identity) cfg.identity = {};
    cfg.identity.worker = { handle: res.data.username, token: res.data.token, createdAt: new Date().toISOString() };
    figSetConfig(cfg);
    if (toast) { toast.className = 'fig-toast ok'; toast.textContent = '✓ Created @' + res.data.username; }
    setTimeout(function() { render(); }, 600);
  }).catch(function(e) {
    if (toast) { toast.className = 'fig-toast err'; toast.textContent = 'Failed: ' + (e.message || e); }
    if (btn) btn.disabled = false;
  });
}

function figSignOut() {
  var cfg = figGetConfig();
  if (cfg.identity && cfg.identity.email) delete cfg.identity.email;
  figSetConfig(cfg);
  figClearSession();
  render();
}

function figIdentCreateAccount() {
  var email = document.getElementById('fig-ident-email');
  var pass = document.getElementById('fig-ident-pass');
  var toast = document.getElementById('fig-ident-email-toast');
  if (!email || !pass || !toast) return;
  var e = email.value.trim(), p = pass.value;
  if (!e || !p) { toast.className = 'fig-toast err'; toast.textContent = 'Email and password required.'; return; }
  toast.className = 'fig-toast'; toast.textContent = 'Signing in…';
  figSimpleHash(p).then(function(hash) {
    var key = 'fig_login_' + e.toLowerCase();
    var existing = localStorage.getItem(key);
    if (existing) {
      var d = JSON.parse(existing);
      if (d.hash !== hash) { toast.className = 'fig-toast err'; toast.textContent = 'Wrong password.'; return; }
    } else {
      localStorage.setItem(key, JSON.stringify({ hash: hash, createdAt: new Date().toISOString() }));
    }
    var cfg = figGetConfig();
    if (!cfg.identity) cfg.identity = {};
    cfg.identity.email = { address: e.toLowerCase(), createdAt: existing ? JSON.parse(existing).createdAt : new Date().toISOString() };
    figSetConfig(cfg);
    figSetSession({ email: e.toLowerCase(), loggedInAt: new Date().toISOString() });
    toast.className = 'fig-toast ok';
    toast.textContent = existing ? '✓ Signed in' : '✓ Account created';
    setTimeout(function() { render(); }, 500);
  }).catch(function(err) {
    toast.className = 'fig-toast err'; toast.textContent = 'Error: ' + (err.message || err);
  });
}

function figRenderWorkerOption() {
  var el = document.getElementById('fig-acc-worker-option');
  if (!el) return;
  var sync = figGetSync();
  var hasWorkerUrl = sync && sync.workerUrl;
  el.innerHTML = hasWorkerUrl ? `
    <div class="fig-field">
      <label>Fig Handle</label>
      <input id="fig-acc-worker-handle" type="text" placeholder="e.g. gg" maxlength="32" autocomplete="off" onkeydown="if(event.key==='Enter')figCreateWorkerAccount()">
      <div class="fig-field-help">2–32 characters: letters, numbers, _ and -</div>
    </div>
    <div class="fig-btn-row" style="padding-top:0">
      <button class="fig-btn primary" onclick="figCreateWorkerAccount()" style="padding:8px 18px;font-size:0.68rem">Create Handle</button>
    </div>` : `
    <div style="background:var(--surface2,#1a1a26);padding:12px 14px;border-radius:8px;font-size:0.68rem;line-height:1.7">
      To create a Fig Handle, deploy the Fig Worker and set the Worker URL in <b>Settings → Cloud sync</b>.
    </div>`;
}

// ── Identity step ─────────────────────────────
function figRenderIdentity() {
  var cfg = figGetConfig();
  var ident = cfg.identity || {};
  var session = figGetSession();
  var emailConnected = session && session.email;
  var widConnected = ident.worldid && ident.worldid.nullifier_hash;
  var bskyConnected = ident.bsky && ident.bsky.handle && ident.bsky.accessJwt;
  var workerConnected = ident.worker && ident.worker.handle && ident.worker.token;

  return `
    <div class="fig-field" style="margin-bottom:16px">
      <label style="font-size:0.6rem;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted);margin-bottom:8px">Account</label>
      ${emailConnected ? `
        <div style="display:flex;align-items:center;justify-content:space-between;background:var(--surface2,#1a1a26);border:1px solid var(--border,#252535);border-radius:8px;padding:10px 14px;font-size:0.78rem">
          <span>Signed in as <b>${session.email}</b></span>
          <button class="fig-btn danger" style="padding:4px 10px;font-size:0.55rem" onclick="figSignOut()">Sign out</button>
        </div>` : `
        <div style="background:var(--surface2,#1a1a26);border:1px solid var(--border,#252535);border-radius:8px;padding:14px;font-size:0.72rem;line-height:1.7">
          <div style="margin-bottom:10px">Sign in with email to save your account locally. No server needed — your data stays with you.</div>
          <div class="fig-field" style="margin-bottom:8px">
            <label>Email</label>
            <input id="fig-ident-email" type="email" placeholder="you@example.com" autocomplete="email" onkeydown="if(event.key==='Enter')document.getElementById('fig-ident-pass').focus()">
          </div>
          <div class="fig-field" style="margin-bottom:8px">
            <label>Password</label>
            <input id="fig-ident-pass" type="password" placeholder="Choose a password" autocomplete="new-password" onkeydown="if(event.key==='Enter')figIdentCreateAccount()">
          </div>
          <div class="fig-btn-row" style="padding-top:0">
            <button class="fig-btn primary" onclick="figIdentCreateAccount()" style="padding:6px 16px;font-size:0.65rem">Sign up / Sign in</button>
            <span id="fig-ident-email-toast" class="fig-toast" style="min-height:0;flex:1"></span>
          </div>
        </div>`}
    </div>
    <hr style="border:none;border-top:1px solid var(--border,#252535);margin:12px 0">
    <div class="fig-h2">Connect identity</div>
    <div class="fig-desc">Link your identity for attestations and decentralized cred.</div>
    <div class="fig-grid" style="grid-template-columns:1fr">
      <div class="fig-card ${widConnected?'selected':''}" onclick="figToggleWid()" style="display:flex;align-items:center;gap:12px;padding:12px 14px">
        <span style="font-size:1.2rem">🌐</span>
        <div style="flex:1">
          <div class="fig-card-name">World ID</div>
          <div class="fig-card-desc">${widConnected ? 'Verified (' + (ident.worldid.verification_level || 'human') + ')' : 'Proof of personhood — scan with World App'}</div>
        </div>
        <span style="font-size:0.7rem;color:${widConnected ? 'var(--green,#7ec8a0)' : 'var(--muted,#6b6880)'}">${widConnected ? '✓ connected' : 'connect'}</span>
        ${widConnected ? '<button class="fig-btn danger" style="padding:4px 8px;font-size:0.55rem" onclick="event.stopPropagation();figDisconnectWid()">✕</button>' : ''}
      </div>
      <div class="fig-card ${bskyConnected?'selected':''}" onclick="figToggleBsky()" style="display:flex;align-items:center;gap:12px;padding:12px 14px">
        <span style="font-size:1.2rem">🦋</span>
        <div style="flex:1">
          <div class="fig-card-name">Bluesky</div>
          <div class="fig-card-desc">${bskyConnected ? '@' + ident.bsky.handle : 'Decentralized identity via AT Protocol'}</div>
        </div>
        <span style="font-size:0.7rem;color:${bskyConnected ? 'var(--green,#7ec8a0)' : 'var(--muted,#6b6880)'}">${bskyConnected ? '✓ connected' : 'connect'}</span>
        ${bskyConnected ? '<button class="fig-btn danger" style="padding:4px 8px;font-size:0.55rem" onclick="event.stopPropagation();figDisconnectBsky()">✕</button>' : ''}
      </div>
    </div>
    <div id="fig-ident-form"></div>
    <div id="fig-ident-toast" class="fig-toast"></div>
    <div class="fig-btn-row">
      <button class="fig-btn ghost" onclick="prevStep()">← Back</button>
      <span class="fig-spacer"></span>
      <button class="fig-btn primary" onclick="nextStep()">${_isSettings ? 'Done' : 'Next →'}</button>
    </div>`;
}

function figToggleWorker() {
  var cfg = figGetConfig();
  if (cfg.identity && cfg.identity.worker && cfg.identity.worker.handle) {
    return; // already connected
  }
  var handle = prompt('Choose a handle (2-32 chars, letters/numbers/_-):');
  if (!handle) return;
  if (!/^[a-zA-Z0-9_-]{2,32}$/.test(handle)) { alert('Invalid handle. Use letters, numbers, _ and - (2-32 chars).'); return; }
  var sync = figGetSync();
  var workerUrl = sync && sync.workerUrl;
  if (!workerUrl) {
    alert('Set a Worker URL in Settings → Cloud sync first, then come back to create a handle.');
    return;
  }
  var toast = document.getElementById('fig-ident-toast');
  if (toast) toast.textContent = 'Creating…';
  fetch(workerUrl.replace(/\/$/, '') + '/auth/register', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: handle })
  }).then(function(r) { return r.json().then(function(d) { return { ok: r.ok, status: r.status, data: d }; }); })
  .then(function(res) {
    if (!res.ok) {
      if (res.status === 409) { alert('Handle taken. Try another or paste your existing token.'); return; }
      throw new Error(res.data.error || ('HTTP ' + res.status));
    }
    var cfg2 = figGetConfig();
    if (!cfg2.identity) cfg2.identity = {};
    cfg2.identity.worker = { handle: res.data.username, token: res.data.token, createdAt: new Date().toISOString() };
    figSetConfig(cfg2);
    if (toast) { toast.className = 'fig-toast ok'; toast.textContent = '✓ Connected as @' + res.data.username; }
    render();
  }).catch(function(e) {
    if (toast) { toast.className = 'fig-toast err'; toast.textContent = 'Failed: ' + (e.message || e); }
  });
}

function figDisconnectWorker() {
  if (!confirm('Disconnect Fig Handle?')) return;
  var cfg = figGetConfig();
  if (cfg.identity) delete cfg.identity.worker;
  figSetConfig(cfg);
  render();
}

var _bskyFormRendered = false;
function figRenderBskyForm() {
  var wrap = document.getElementById('fig-ident-form');
  if (!wrap) return;
  _bskyFormRendered = true;
  wrap.innerHTML = '<div style="margin-top:8px;padding:14px;background:var(--surface2,#1a1a26);border-radius:10px">' +
    '<label style="display:block;font-size:0.6rem;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted,#6b6880);margin-bottom:4px">Bluesky Handle</label>' +
    '<input id="fig-bsky-handle" type="text" placeholder="alice.bsky.social" style="width:100%;background:var(--surface,#12121a);border:1px solid var(--border,#252535);border-radius:6px;padding:8px 10px;color:var(--text,#e8e4f0);font-family:inherit;font-size:0.75rem;outline:none;margin-bottom:10px;box-sizing:border-box">' +
    '<label style="display:block;font-size:0.6rem;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted,#6b6880);margin-bottom:4px">App Password</label>' +
    '<input id="fig-bsky-pass" type="password" placeholder="xxxx-xxxx-xxxx-xxxx" style="width:100%;background:var(--surface,#12121a);border:1px solid var(--border,#252535);border-radius:6px;padding:8px 10px;color:var(--text,#e8e4f0);font-family:inherit;font-size:0.75rem;outline:none;margin-bottom:10px;box-sizing:border-box">' +
    '<div style="display:flex;gap:8px;align-items:center">' +
    '<button class="fig-btn primary" onclick="figConnectBsky()" style="padding:7px 16px;font-size:0.62rem">Connect</button>' +
    '<button class="fig-btn ghost" onclick="figCancelBskyForm()" style="padding:7px 8px;font-size:0.62rem">Cancel</button>' +
    '<span id="fig-bsky-toast" class="fig-toast" style="min-height:0"></span>' +
    '</div></div>';
  setTimeout(function() { var el = document.getElementById('fig-bsky-handle'); if (el) el.focus(); }, 100);
}
function figToggleBsky() {
  var cfg = figGetConfig();
  if (cfg.identity && cfg.identity.bsky && cfg.identity.bsky.handle) return;
  if (_bskyFormRendered) return;
  figRenderBskyForm();
}
function figConnectBsky() {
  var handle = document.getElementById('fig-bsky-handle')?.value?.trim().replace(/^@/, '');
  var pass = document.getElementById('fig-bsky-pass')?.value;
  var toast = document.getElementById('fig-bsky-toast') || document.getElementById('fig-ident-toast');
  if (!handle || !pass) { if (toast) { toast.className = 'fig-toast err'; toast.textContent = 'Both fields required.'; } return; }
  if (toast) { toast.className = 'fig-toast'; toast.textContent = 'Connecting…'; }
  fetch('https://bsky.social/xrpc/com.atproto.server.createSession', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier: handle, password: pass })
  }).then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
  .then(function(res) {
    if (!res.ok) throw new Error(res.data.message || res.data.error || 'Auth failed');
    var cfg2 = figGetConfig();
    if (!cfg2.identity) cfg2.identity = {};
    cfg2.identity.bsky = { did: res.data.did, handle: res.data.handle, accessJwt: res.data.accessJwt, refreshJwt: res.data.refreshJwt, createdAt: new Date().toISOString() };
    figSetConfig(cfg2);
    if (toast) { toast.className = 'fig-toast ok'; toast.textContent = '✓ Connected as @' + res.data.handle; }
    _bskyFormRendered = false;
    render();
  }).catch(function(e) {
    if (toast) { toast.className = 'fig-toast err'; toast.textContent = 'Failed: ' + (e.message || e) + ' (use an app password)'; }
  });
}
function figCancelBskyForm() {
  _bskyFormRendered = false;
  var wrap = document.getElementById('fig-ident-form');
  if (wrap) wrap.innerHTML = '';
}

function figDisconnectBsky() {
  if (!confirm('Disconnect Bluesky?')) return;
  var cfg = figGetConfig();
  if (cfg.identity) delete cfg.identity.bsky;
  figSetConfig(cfg);
  render();
}

async function figToggleWid() {
  var cfg = figGetConfig();
  if (cfg.identity && cfg.identity.worldid && cfg.identity.worldid.nullifier_hash) return;
  var toast = document.getElementById('fig-ident-toast');
  if (!toast) return;
  var ident = cfg.identity || {};
  var sync = figGetSync();
  var appId = cfg.worldIdAppId || '';
  if (!appId && sync.workerUrl) {
    toast.className = 'fig-toast';
    toast.textContent = 'Loading config…';
    try {
      var cfgResp = await fetch(sync.workerUrl.replace(/\/$/, '') + '/config');
      if (cfgResp.ok) { var wcfg = await cfgResp.json(); appId = wcfg.worldIdAppId || ''; }
    } catch (e) {}
  }
  if (!appId) {
    toast.className = 'fig-toast err';
    toast.textContent = 'No World ID App ID. Configure it in Settings → World ID, or set a Worker URL in Cloud sync.';
    return;
  }
  var signal = ident.worker?.handle || 'fig-user';
  var idkit = window.IDKit;
  if (!idkit) {
    toast.textContent = 'Waiting for IDKit library…';
    for(var _i=0;_i<50;_i++){await new Promise(function(r){setTimeout(r,100)});idkit=window.IDKit;if(idkit)break;}
  }
  if (!idkit) { toast.className = 'fig-toast err'; toast.textContent = 'IDKit not loaded after 5s. Check your network or refresh. If you use a content blocker, allow cdn.jsdelivr.net.'; return; }
  toast.textContent = 'Open World App on your phone to scan the QR…';
  try {
    var result = await idkit.init({
      app_id: appId,
      action: 'verify-human',
      signal: signal,
      verification_level: 'orb',
    });
    var cfg2 = figGetConfig();
    if (!cfg2.identity) cfg2.identity = {};
    cfg2.identity.worldid = { nullifier_hash: result.nullifier_hash, verification_level: result.verification_level || 'orb', verifiedAt: new Date().toISOString() };
    cfg2.worldIdAppId = appId;
    figSetConfig(cfg2);
    toast.className = 'fig-toast ok';
    toast.textContent = 'Verified.';
    render();
    if (sync.workerUrl && ident.worker?.token) {
      toast.textContent = 'Syncing with Worker…';
      try {
        await fetch(sync.workerUrl.replace(/\/$/, '') + '/auth/worldid/verify', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + ident.worker.token, 'Content-Type': 'application/json' },
          body: JSON.stringify({ proof: result, action: 'verify-human', signal: signal })
        });
        toast.className = 'fig-toast ok';
        toast.textContent = 'Verified + synced.';
      } catch(e) { toast.textContent = 'Verified locally (Worker sync failed).'; }
    }
  } catch (e) {
    toast.className = 'fig-toast err';
    toast.textContent = 'Failed: ' + (e.message || e);
  }
}

function figDisconnectWid() {
  if (!confirm('Disconnect World ID?')) return;
  var cfg = figGetConfig();
  if (cfg.identity) delete cfg.identity.worldid;
  figSetConfig(cfg);
  render();
}

// ── LLM step ──────────────────────────────────
function figRenderLLM() {
  var cfg = figGetConfig();
  var llm = cfg.llm || {};
  var connected = llm && llm.provider && llm.key;
  return `
    <div class="fig-h2">Bring your own LLM key</div>
    <div class="fig-desc">Fig uses <b>your</b> key — never ours. Stored locally in your browser, never sent to any server.<br>
    Pick a provider and paste your API key.</div>
    <div class="fig-grid" id="fig-provider-grid">
      ${FIG_PROVIDERS.map(function(p) {
        var active = (llm.provider === p.id) ? ' selected' : '';
        return '<div class="fig-card' + active + '" onclick="figPickProvider(\'' + p.id + '\')">' +
          '<div class="fig-card-name">' + p.name + '</div>' +
          '<div class="fig-card-desc">' + p.desc + '</div>' +
        '</div>';
      }).join('')}
    </div>
    <div id="fig-llm-fields">
      ${figLLMFields()}
    </div>
    <div id="fig-llm-toast" class="fig-toast"></div>
    <div class="fig-btn-row">
      <button class="fig-btn ghost" onclick="prevStep()">← Back</button>
      <span class="fig-spacer"></span>
      ${connected ? '<span style="font-size:0.68rem;color:var(--green,#7ec8a0)">✓ connected</span>' : ''}
      <button class="fig-btn primary" onclick="figSaveLLM()">Save</button>
    </div>`;
}

function figLLMFields() {
  var cfg = figGetConfig();
  var llm = cfg.llm || {};
  var p = FIG_PROVIDERS.find(function(q) { return q.id === llm.provider; }) || FIG_PROVIDERS[0];
  var isOllama = p.id === 'ollama';
  return '<div class="fig-field">' +
    (!isOllama ? '<label>API key</label><input id="fig-llm-key" type="password" placeholder="' + p.keyPlaceholder + '" value="' + (llm.key || '') + '" autocomplete="off"><div class="fig-field-help"><a href="' + (p.id === 'anthropic' ? 'https://console.anthropic.com/settings/keys' : p.id === 'openrouter' ? 'https://openrouter.ai/keys' : p.id === 'openai' ? 'https://platform.openai.com/api-keys' : '') + '" target="_blank">Get a key →</a></div>' : '') +
    '<label>Base URL' + (isOllama ? '' : ' (advanced)') + '</label>' +
    '<input id="fig-llm-base" type="text" placeholder="' + p.defaultBase + '" value="' + (llm.baseUrl || p.defaultBase) + '" autocomplete="off">' +
    '<div class="fig-field-help">' + (isOllama ? 'Default Ollama runs on localhost:11434. Make sure <code>ollama serve</code> is running.' : 'Leave default unless you proxy through your own gateway.') + '</div>' +
    '</div>' +
    '<div class="fig-btn-row" style="margin-top:0;padding-top:4px">' +
    '<button class="fig-btn secondary" onclick="figTestLLM()" style="padding:6px 14px;font-size:0.62rem">Test connection</button>' +
    '</div>';
}

function figPickProvider(id) {
  var cfg = figGetConfig();
  if (!cfg.llm) cfg.llm = {};
  cfg.llm.provider = id;
  var p = FIG_PROVIDERS.find(function(q) { return q.id === id; });
  if (p && (!cfg.llm.baseUrl || FIG_PROVIDERS.some(function(q) { return q.defaultBase === cfg.llm.baseUrl; }))) {
    cfg.llm.baseUrl = p.defaultBase;
  }
  figSetConfig(cfg);
  render();
}

function figSaveLLM() {
  var cfg = figGetConfig();
  if (!cfg.llm) cfg.llm = {};
  var k = document.getElementById('fig-llm-key');
  var b = document.getElementById('fig-llm-base');
  if (k) cfg.llm.key = k.value.trim();
  if (b) cfg.llm.baseUrl = b.value.trim() || (FIG_PROVIDERS.find(function(p) { return p.id === cfg.llm.provider; }) || {}).defaultBase;
  if (!cfg.llm.provider) cfg.llm.provider = 'anthropic';
  figSetConfig(cfg);
  var toast = document.getElementById('fig-llm-toast');
  if (toast) { toast.className = 'fig-toast ok'; toast.textContent = 'Saved.'; }
}

async function figTestLLM() {
  figSaveLLM();
  var cfg = figGetConfig();
  var llm = cfg.llm || {};
  var toast = document.getElementById('fig-llm-toast');
  if (!toast) return;
  toast.className = 'fig-toast';
  toast.textContent = 'Pinging…';
  try {
    var msg = await window.figTestLLM(llm);
    toast.className = 'fig-toast ok';
    toast.textContent = msg;
  } catch (e) {
    toast.className = 'fig-toast err';
    toast.textContent = 'Failed: ' + (e.message || e);
  }
}

// ── Done step ─────────────────────────────────
function figRenderDone() {
  var cfg = figGetConfig();
  var ident = cfg.identity || {};
  var llm = cfg.llm || {};
  var wid = ident.worldid && ident.worldid.nullifier_hash ? '✓ World ID verified' : '○ skipped';
  var llmStatus = llm.provider && llm.key ? '✓ ' + (FIG_PROVIDERS.find(function(p) { return p.id === llm.provider; }) || {}).name + ' connected' : '○ skipped';

  return `
    <div class="fig-h2">You're set</div>
    <div class="fig-desc">Here's what you configured. You can always change these from the <b>⚙</b> icon in the top-left corner of any page.</div>
    <div class="fig-done-grid">
      <div class="fig-done-item ${wid.startsWith('✓')?'done':'skipped'}"><span class="fig-done-icon">🌐</span> ${wid}</div>
      <div class="fig-done-item ${llmStatus.startsWith('✓')?'done':'skipped'}"><span class="fig-done-icon">🔑</span> ${llmStatus}</div>
    </div>
    <div class="fig-btn-row">
      <button class="fig-btn ghost" onclick="prevStep()">← Back</button>
      <span class="fig-spacer"></span>
      <button class="fig-btn primary" onclick="figDismissLauncher()">Start using Fig →</button>
    </div>`;
}

// ── Modal lifecycle ───────────────────────────
function showFigLauncher() {
  _step = 0;
  _isSettings = false;
  var overlay = document.createElement('div');
  overlay.className = 'fig-overlay';
  overlay.innerHTML = '<div class="fig-launcher" id="fig-launcher-inner"><button class="fig-close" onclick="closeFigLauncher()">✕</button><div id="fig-launcher-content"></div></div>';
  overlay.addEventListener('click', function(e) { if (e.target === overlay) closeFigLauncher(); });
  document.body.appendChild(overlay);
  _overlayEl = overlay;
  _launcherEl = document.getElementById('fig-launcher-content');
  requestAnimationFrame(function() { overlay.classList.add('open'); });
  render();
}

function closeFigLauncher() {
  if (_overlayEl) {
    _overlayEl.classList.remove('open');
    var el = _overlayEl;
    setTimeout(function() { if (el.parentNode) el.parentNode.removeChild(el); }, 250);
  }
  _overlayEl = null;
  _launcherEl = null;
}

function figDismissLauncher() {
  var cfg = figGetConfig();
  cfg.launched = true;
  figSetConfig(cfg);
  closeFigLauncher();
  updateSentry();
}

// ── Settings re-open ──────────────────────────
function openFigSettings() {
  if (_overlayEl) { closeFigLauncher(); return; }
  _step = 0;
  _isSettings = true;
  var overlay = document.createElement('div');
  overlay.className = 'fig-overlay';
  overlay.innerHTML = '<div class="fig-launcher" id="fig-launcher-inner"><button class="fig-close" onclick="closeFigLauncher()">✕</button><div style="margin-bottom:6px"><div class="fig-wordmark" style="font-size:1.1rem">Fig</div><div class="fig-wordmark-tag" style="font-size:0.5rem">Settings</div></div><div id="fig-launcher-content"></div></div>';
  overlay.addEventListener('click', function(e) { if (e.target === overlay) closeFigLauncher(); });
  document.body.appendChild(overlay);
  _overlayEl = overlay;
  _launcherEl = document.getElementById('fig-launcher-content');
  requestAnimationFrame(function() { overlay.classList.add('open'); });
  render();
}

// ── Sentry (persistent settings button) ───────
function injectSentry() {
  var existing = document.querySelector('.fig-sentry');
  if (existing) return;
  var sentry = document.createElement('div');
  sentry.className = 'fig-sentry';
  sentry.id = 'fig-sentry';
  var nav = (typeof navigateTo === 'function') ? 'navigateTo(\'dashboard\')' : 'window.location.href=\'index.html\'';
  sentry.innerHTML =
    '<button class="fig-sentry-btn" onclick="' + nav + '" style="font-family:\'Fraunces\',serif;letter-spacing:-0.02em;font-size:0.75rem;text-transform:none;padding:3px 9px">Fig</button>' +
    '<button class="fig-sentry-btn" onclick="openFigSettings()">⚙</button>';
  document.body.appendChild(sentry);
}

function updateSentry() {
  var cfg = figGetConfig();
  var ident = cfg.identity || {};
  var llm = cfg.llm || {};
  var sentry = document.getElementById('fig-sentry');
  if (!sentry) return;
  var widDot = ident.worldid && ident.worldid.nullifier_hash ? 'wid' : '';
  var llmDot = llm.provider && llm.key ? 'llm' : '';
  var nav = (typeof navigateTo === 'function') ? 'navigateTo(\'dashboard\')' : 'window.location.href=\'index.html\'';
  sentry.innerHTML =
    '<button class="fig-sentry-btn" onclick="' + nav + '" style="font-family:\'Fraunces\',serif;letter-spacing:-0.02em;font-size:0.75rem;text-transform:none;padding:3px 9px">Fig</button>' +
    '<button class="fig-sentry-btn" onclick="openFigSettings()">⚙' +
    (widDot || llmDot ? ' <span class="fig-dot-online ' + widDot + '"></span>' : '') +
    '</button>';
}

// ── First launch check ────────────────────────
function checkFigLauncher() {
  injectStyles();
  var cfg = figGetConfig();
  if (!cfg.launched) {
    showFigLauncher();
  }
  // We don't auto-inject sentry — each page handles its own trigger area.
  // But we keep updateSentry available for the settings trigger.
  window.openFigSettings = openFigSettings;
  window.figDismissLauncher = figDismissLauncher;
  window.figSignOut = figSignOut;
  window.figIdentCreateAccount = figIdentCreateAccount;
  window.figCreateEmailAccount = figCreateEmailAccount;
  window.figSimpleHash = figSimpleHash;
  window.closeFigLauncher = closeFigLauncher;
  window.figToggleWorker = figToggleWorker;
  window.figDisconnectWorker = figDisconnectWorker;
  window.figToggleBsky = figToggleBsky;
  window.figConnectBsky = figConnectBsky;
  window.figCancelBskyForm = figCancelBskyForm;
  window.figDisconnectBsky = figDisconnectBsky;
  window.figToggleWid = figToggleWid;
  window.figDisconnectWid = figDisconnectWid;
  window.figPickProvider = figPickProvider;
  window.figSaveLLM = figSaveLLM;
  window.figTestLLM = figTestLLM;
  window.nextStep = nextStep;
  window.prevStep = prevStep;
  window.figGetConfig = figGetConfig;
  window.setFigConfig = figSetConfig;
  window.updateSentry = updateSentry;
  window.navigateTo = window.navigateTo || function(v) { window.location.hash = v; };
}

// Auto-run on DOMContentLoaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', checkFigLauncher);
} else {
  checkFigLauncher();
}

})();
