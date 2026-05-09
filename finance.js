'use strict';

const DB_NAME = 'fig_v1';
const DB_VERSION = 2;
let db = null;
let charts = {};
let dashConfig = null;
let dashMonths = {};
let chatHistory = [];
let obState = {
  step: 0,
  answers: {},
  freeTexts: {},
  template: null,
  llmConfig: null,
  profile: {},
};
let obSteps = ['intro','q1','q2','q3','q4','q5','q6','api','profile','confirm'];
let obCurrentIdx = 0;

const FINANCE_PROVIDERS = {
  anthropic: { label:'Claude (Anthropic)', placeholder:'sk-ant-...', baseUrl:'https://api.anthropic.com' },
  openai:    { label:'ChatGPT (OpenAI)',   placeholder:'sk-...',     baseUrl:'https://api.openai.com/v1' },
  gemini:    { label:'Gemini (Google)',    placeholder:'AIza...',    baseUrl:'https://generativelanguage.googleapis.com' },
  deepseek:  { label:'DeepSeek',          placeholder:'sk-...',     baseUrl:'https://api.deepseek.com/v1' },
};

const LS = {
  get: k => { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
};

(function applySavedTheme(){
  try {
    const raw = localStorage.getItem('fig_theme_v1');
    if (!raw) return;
    const t = JSON.parse(raw);
    const r = document.documentElement;
    Object.entries(t).forEach(([k,v]) => { if (k !== 'name' && typeof v === 'string') r.style.setProperty('--' + k, v); });
    if (t.accent) {
      r.style.setProperty('--accent-dim', t.accent + '22');
      r.style.setProperty('--accent-mid', t.accent + '44');
    }
  } catch (e) {}
})();

window.figEmergencyReset = function() {
  if (!confirm('Reset Fig and clear all local data? This will not affect your remote backups.')) return;
  try { indexedDB.deleteDatabase('fig_v1'); } catch (e) {}
  try { localStorage.clear(); } catch (e) {}
  window.location.reload();
};

async function openDB() {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined' || !indexedDB) {
      reject(new Error('IndexedDB is not available. Try a different browser, leave private/incognito mode, or open Fig over http(s) instead of file://.'));
      return;
    }
    let req;
    try { req = indexedDB.open(DB_NAME, DB_VERSION); }
    catch (e) { reject(new Error('IndexedDB open failed: ' + (e && e.message || e))); return; }
    const timer = setTimeout(() => reject(new Error('IndexedDB open timed out. Try Reset, or open in a regular browser window.')), 5000);
    req.onupgradeneeded = e => {
      const d = e.target.result;
      if (!d.objectStoreNames.contains('config')) d.createObjectStore('config');
      if (!d.objectStoreNames.contains('months')) d.createObjectStore('months');
      if (!d.objectStoreNames.contains('chat')) d.createObjectStore('chat', {keyPath:'id',autoIncrement:true});
      if (!d.objectStoreNames.contains('snapshots')) d.createObjectStore('snapshots', {keyPath:'ts'});
    };
    req.onsuccess = e => { clearTimeout(timer); resolve(e.target.result); };
    req.onerror   = ()=> { clearTimeout(timer); reject(req.error || new Error('IndexedDB open errored')); };
    req.onblocked = ()=> { clearTimeout(timer); reject(new Error('IndexedDB open is blocked by another tab using Fig. Close other Fig tabs and reload.')); };
  });
}

async function dbGet(store, key) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbPut(store, value, key) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    const req = key !== undefined ? tx.objectStore(store).put(value, key) : tx.objectStore(store).put(value);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

async function dbGetAll(store) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).getAll();
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbGetAllKeys(store) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).getAllKeys();
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function callLLM(systemPrompt, userMessage, expectJSON = false) {
  const provider = LS.get('fig_provider') || 'anthropic';
  const key = LS.get('fig_key');
  if (!key) throw new Error('No API key');

  let content = '';
  if (provider === 'anthropic') {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type':'application/json','x-api-key':key,'anthropic-version':'2023-06-01','anthropic-dangerous-direct-browser-access':'true' },
      body: JSON.stringify({ model:'claude-3-5-haiku-20241022', max_tokens:1024, system:systemPrompt, messages:[{role:'user',content:userMessage}] })
    });
    const d = await res.json();
    if (d.error) throw new Error(d.error.message);
    content = d.content?.[0]?.text || '';
  } else if (provider === 'openai' || provider === 'deepseek') {
    const base = FINANCE_PROVIDERS[provider].baseUrl;
    const model = provider === 'deepseek' ? 'deepseek-chat' : 'gpt-4o-mini';
    const res = await fetch(`${base}/chat/completions`, {
      method:'POST', headers:{'Content-Type':'application/json','Authorization':`Bearer ${key}`},
      body:JSON.stringify({model,max_tokens:1024,messages:[{role:'system',content:systemPrompt},{role:'user',content:userMessage}]})
    });
    const d = await res.json();
    if (d.error) throw new Error(d.error.message);
    content = d.choices?.[0]?.message?.content || '';
  } else if (provider === 'gemini') {
    const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${key}`, {
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({contents:[{role:'user',parts:[{text:`${systemPrompt}\n\n${userMessage}`}]}]})
    });
    const d = await res.json();
    if (d.error) throw new Error(d.error.message);
    content = d.candidates?.[0]?.content?.parts?.[0]?.text || '';
  }
  if (expectJSON) {
    content = content.replace(/```json\n?/g,'').replace(/```\n?/g,'').trim();
    return JSON.parse(content);
  }
  return content;
}

const QUESTIONS = [
  {
    id: 'q1',
    text: 'What is your financial objective?',
    desc: 'This shapes everything — what modules appear, what targets get set, how progress is measured.',
    choices: [
      { val:'property', label:'Buy a property' },
      { val:'trip',     label:'Save for a big trip or experience' },
      { val:'debt',     label:'Pay off debt' },
      { val:'runway',   label:'Build a safety net / emergency fund' },
      { val:'understand', label:'Understand my finances — no specific goal yet' },
    ],
    freeTextLabel: 'Something else? Describe it',
  },
  {
    id: 'q2',
    text: 'Do you have a target date in mind?',
    desc: 'This determines how Fig calculates your path — either working backwards from a deadline, or forwards from your savings rate.',
    choices: [
      { val:'fixed',  label:'Yes — I have a specific target date' },
      { val:'open',   label:'No — show me when I\'ll get there at my current pace' },
      { val:'suggest', label:'Not sure — suggest a realistic timeline' },
    ],
  },
  {
    id: 'q3',
    text: 'What is your approximate monthly take-home pay?',
    desc: 'After tax, after retirement contributions — what actually lands in your account.',
    choices: [
      { val:'<3000',    label:'Under $3,000 / month' },
      { val:'3-5k',     label:'$3,000 – $5,000 / month' },
      { val:'5-8k',     label:'$5,000 – $8,000 / month' },
      { val:'8-12k',    label:'$8,000 – $12,000 / month' },
      { val:'12-20k',   label:'$12,000 – $20,000 / month' },
      { val:'>20k',     label:'Over $20,000 / month' },
    ],
    freeTextLabel: 'Or enter an exact figure',
    freeTextPlaceholder: 'e.g. 9,500',
  },
  {
    id: 'q4',
    text: 'Do you have fixed recurring costs you want to track?',
    desc: 'Things like rent, loan payments, subscriptions — costs that don\'t change month to month.',
    choices: [
      { val:'yes',  label:'Yes — I\'ll list them' },
      { val:'no',   label:'No fixed costs, or I\'ll add them later' },
    ],
    freeTextLabel: 'List your fixed costs (rent, loans, subscriptions...)',
    freeTextPlaceholder: 'e.g. Rent $2,800, student loan $400, subscriptions $150',
    freeTextConditional: 'yes',
  },
  {
    id: 'q5',
    text: 'Which spending categories matter most to you?',
    desc: 'These get a protected buffer and are highlighted in your dashboard.',
    choices: [
      { val:'food',       label:'Food & dining' },
      { val:'transport',  label:'Transport' },
      { val:'housing',    label:'Housing & utilities' },
      { val:'travel',     label:'Travel & experiences' },
      { val:'health',     label:'Health & fitness' },
      { val:'education',  label:'Education & self-development' },
      { val:'savings',    label:'Savings rate itself' },
    ],
    multiSelect: true,
    freeTextLabel: 'Anything else you want to track closely?',
  },
  {
    id: 'q6',
    text: 'Do you want to track net worth, or just cash flow?',
    desc: 'Net worth adds a snapshot of assets and liabilities.',
    choices: [
      { val:'both',      label:'Both — net worth + cash flow' },
      { val:'cashflow',  label:'Just cash flow for now' },
    ],
  },
];

function renderQuestion(q, step) {
  const isMulti = !!q.multiSelect;
  const currentVals = obState.answers[q.id] || (isMulti ? [] : null);
  const currentFree = obState.freeTexts[q.id] || '';
  const showFreeText = q.freeTextConditional
    ? currentVals === q.freeTextConditional || (isMulti && currentVals.includes(q.freeTextConditional))
    : !!q.freeTextLabel;
  return `
    <div class="q-label">Question ${step} of 6</div>
    <div class="q-text">${q.text}</div>
    <div class="q-desc">${q.desc}</div>
    <div class="choices" id="choices-${q.id}">
      ${q.choices.map(c => {
        const sel = isMulti ? (currentVals||[]).includes(c.val) : currentVals === c.val;
        return `<div class="choice ${sel?'selected':''}" onclick="selectChoice('${q.id}','${c.val}',${isMulti})" data-val="${c.val}">
          <div class="choice-dot"></div>
          <span class="choice-label">${c.label}</span>
        </div>`;
      }).join('')}
    </div>
    ${q.freeTextLabel ? `
    <div class="freetext-wrapper" id="free-${q.id}" style="${showFreeText?'':'display:none'}">
      <div class="freetext-label">↳ ${q.freeTextLabel}</div>
      <textarea class="freetext-input" id="ft-${q.id}" rows="2" placeholder="${q.freeTextPlaceholder||''}">${currentFree}</textarea>
      <div class="freetext-hint">Fig's AI will interpret this.</div>
    </div>` : ''}
    <div class="llm-thinking" id="llm-thinking"><div class="spinner"></div>Fig is interpreting your answers...</div>
    <div class="ob-error" id="ob-error"></div>
  `;
}

function renderTemplateStep() {
  const sel = obState.template;
  const templates = [
    { val:'property', icon:'\u{1F3E1}', name:'Saving for property', desc:'Goal-first. Net worth on. Savings rate emphasis.' },
    { val:'debt',     icon:'\u{1F4B3}', name:'Paying down debt',     desc:'Liability tracking. Spend reduction focus.' },
    { val:'runway',   icon:'\u{1F6DF}', name:'Building a safety net', desc:'Conservative targets. Emergency fund module.' },
    { val:'general',  icon:'\u{1F4CA}', name:'General tracking',     desc:'No specific goal. All modules on. Neutral.' },
  ];
  return `
    <div class="q-label">Quick start</div>
    <div class="q-text">Start from a template instead?</div>
    <div class="q-desc">Pick a profile and we'll skip to a 2-minute setup.</div>
    <div class="template-grid">
      ${templates.map(t => `
        <div class="template-card ${sel===t.val?'selected':''}" onclick="selectTemplate('${t.val}')">
          <div class="t-icon">${t.icon}</div>
          <div class="t-name">${t.name}</div>
          <div class="t-desc">${t.desc}</div>
        </div>`).join('')}
    </div>
    <div class="ob-error" id="ob-error"></div>
  `;
}

function renderAPIStep() {
  const savedProvider = LS.get('fig_provider') || 'anthropic';
  const savedKey = LS.get('fig_key') || '';
  return `
    <div class="q-label">AI setup</div>
    <div class="q-text">Connect your AI key</div>
    <div class="q-desc">Fig uses your own AI key to power the chat panel. Stored only in your browser.</div>
    <div class="api-setup">
      <div class="api-setup-title">API Key</div>
      <div class="api-row">
        <select class="api-select" id="ob-provider" onchange="updateProviderPlaceholder()">
          ${Object.entries(FINANCE_PROVIDERS).map(([k,v])=>`<option value="${k}" ${savedProvider===k?'selected':''}>${v.label}</option>`).join('')}
        </select>
        <input class="api-key-input" type="password" id="ob-key" placeholder="${FINANCE_PROVIDERS[savedProvider].placeholder}" value="${savedKey}">
      </div>
      <div style="font-size:0.63rem;color:var(--muted);line-height:1.7">Your key is sent directly to the AI provider from your browser. Fig never sees it.</div>
    </div>
    <span class="api-skip" onclick="skipAPIStep()">Skip for now — I'll add a key later</span>
    <div class="ob-error" id="ob-error"></div>
  `;
}

function renderProfileStep() {
  const p = obState.profile;
  return `
    <div class="q-label">Optional · Skippable</div>
    <div class="q-text">A bit about you</div>
    <div class="q-desc">Used for benchmark comparisons. Stored locally only.</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
      <div>
        <div class="freetext-label">Location (city / country)</div>
        <input class="freetext-input" id="prof-location" placeholder="e.g. New York, US" value="${p.location||''}">
      </div>
      <div>
        <div class="freetext-label">Age</div>
        <input class="freetext-input" type="number" id="prof-age" placeholder="e.g. 30" value="${p.age||''}">
      </div>
      <div>
        <div class="freetext-label">Employment type</div>
        <select class="freetext-input" id="prof-employment">
          <option value="">Select...</option>
          <option ${p.employment==='salaried'?'selected':''}>Salaried</option>
          <option ${p.employment==='self-employed'?'selected':''}>Self-employed / freelance</option>
          <option ${p.employment==='contractor'?'selected':''}>Contractor</option>
          <option ${p.employment==='student'?'selected':''}>Student</option>
          <option ${p.employment==='other'?'selected':''}>Other</option>
        </select>
      </div>
      <div>
        <div class="freetext-label">Income bracket (annual)</div>
        <select class="freetext-input" id="prof-income">
          <option value="">Select...</option>
          <option ${p.income==='<50k'?'selected':''} value="<50k">Under $50k</option>
          <option ${p.income==='50-100k'?'selected':''} value="50-100k">$50k – $100k</option>
          <option ${p.income==='100-200k'?'selected':''} value="100-200k">$100k – $200k</option>
          <option ${p.income==='200-400k'?'selected':''} value="200-400k">$200k – $400k</option>
          <option ${p.income==='>400k'?'selected':''} value=">400k">Over $400k</option>
        </select>
      </div>
    </div>
    <div class="ob-error" id="ob-error"></div>
  `;
}

function renderConfirmStep(config) {
  return `
    <div class="q-label">Almost there</div>
    <div class="q-text">Here's what Fig set up for you</div>
    <div class="q-desc">Review your config. You can change any of this later by chatting with Fig.</div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:20px">
      ${[
        ['Goal', config.goalName || 'Not set'],
        ['Monthly take-home', config.takeHome ? fmt(config.takeHome) : 'To be confirmed'],
        ['Fixed costs / month', config.fixedTotal ? fmt(config.fixedTotal) : 'To be confirmed'],
        ['Priority categories', (config.priorityCats||[]).join(', ') || 'None set'],
        ['Net worth module', config.showNetWorth ? 'On' : 'Off'],
        ['Target', config.targetAmount ? fmt(config.targetAmount) + (config.targetYear ? ` by ${config.targetYear}` : '') : 'Not set'],
        ['AI key', LS.get('fig_key') ? '\u2713 Connected' : '\u2014 Not set (add later in chat)'],
      ].map(([k,v]) => `
        <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border);font-size:0.75rem">
          <span style="color:var(--muted)">${k}</span><span>${v}</span>
        </div>`).join('')}
    </div>
    <div class="ob-error" id="ob-error"></div>
  `;
}

function getProgress(idx) { return Math.round((idx / (obSteps.length - 1)) * 100); }

function renderOBStep() {
  const step = obSteps[obCurrentIdx];
  document.getElementById('ob-progress').style.width = getProgress(obCurrentIdx) + '%';
  const content = document.getElementById('ob-content');
  if (step === 'intro') {
    content.innerHTML = `
      <div class="q-text" style="font-size:1.6rem;margin-bottom:12px">Hello.</div>
      <div class="q-desc" style="font-size:0.85rem;max-width:440px">
        Fig builds a personal finance dashboard from your answers. Everything stays on your device.
        Setup takes about 3 minutes.
      </div>
      <div style="margin:32px 0">${renderTemplateStep()}</div>
      <div class="btn-row" style="justify-content:flex-end">
        <button class="btn btn-secondary" onclick="advanceOB()">Answer questions instead \u2192</button>
      </div>`;
    return;
  }
  if (step === 'api') {
    content.innerHTML = renderAPIStep() + `<div class="btn-row"><button class="btn btn-secondary" onclick="retreatOB()">\u2190 Back</button><button class="btn btn-primary" onclick="saveAPIStep()">Continue \u2192</button></div>`;
    return;
  }
  if (step === 'profile') {
    content.innerHTML = renderProfileStep() + `<div class="btn-row"><button class="btn btn-secondary" onclick="retreatOB()">\u2190 Back</button><button class="btn btn-primary" onclick="saveProfileStep()">Continue \u2192</button><button class="btn btn-secondary" onclick="skipProfileStep()">Skip</button></div>`;
    return;
  }
  if (step === 'confirm') {
    content.innerHTML = renderConfirmStep(obState.llmConfig || {}) + `<div class="btn-row"><button class="btn btn-secondary" onclick="retreatOB()">\u2190 Back</button><button class="btn btn-primary" id="launch-btn" onclick="launchDashboard()">Launch my dashboard \u2192</button></div>`;
    return;
  }
  const qIdx = parseInt(step.slice(1)) - 1;
  const q = QUESTIONS[qIdx];
  const stepNum = obCurrentIdx;
  content.innerHTML = renderQuestion(q, stepNum) + `<div class="btn-row"><button class="btn btn-secondary" onclick="retreatOB()">\u2190 Back</button><button class="btn btn-primary" id="q-next-btn" onclick="advanceQuestion('${q.id}')">Continue \u2192</button></div>`;
}

function selectChoice(qid, val, isMulti) {
  if (isMulti) {
    const curr = obState.answers[qid] || [];
    obState.answers[qid] = curr.includes(val) ? curr.filter(v=>v!==val) : [...curr, val];
  } else {
    obState.answers[qid] = val;
  }
  const q = QUESTIONS.find(q=>q.id===qid);
  document.querySelectorAll(`#choices-${qid} .choice`).forEach(el => {
    const v = el.dataset.val;
    const sel = isMulti ? (obState.answers[qid]||[]).includes(v) : obState.answers[qid] === v;
    el.classList.toggle('selected', sel);
    el.querySelector('.choice-dot').style.background = sel ? 'var(--accent)' : '';
    el.querySelector('.choice-dot').style.borderColor = sel ? 'var(--accent)' : '';
  });
  if (q && q.freeTextConditional) {
    const show = isMulti
      ? (obState.answers[qid]||[]).includes(q.freeTextConditional)
      : obState.answers[qid] === q.freeTextConditional;
    const el = document.getElementById(`free-${qid}`);
    if (el) el.style.display = show ? '' : 'none';
  }
}

function selectTemplate(val) {
  obState.template = obState.template === val ? null : val;
  document.querySelectorAll('.template-card').forEach(el => {
    el.classList.toggle('selected', el.onclick && el.onclick.toString().includes(`'${val}'`) && obState.template === val);
  });
  document.querySelectorAll('.template-card').forEach(el => {
    const v = el.querySelector('.t-name').textContent;
    const templates = {'Saving for property':'property','Paying down debt':'debt','Building a safety net':'runway','General tracking':'general'};
    el.classList.toggle('selected', templates[v] === obState.template);
  });
}

async function advanceQuestion(qid) {
  const q = QUESTIONS.find(q=>q.id===qid);
  const errEl = document.getElementById('ob-error');
  if (errEl) errEl.textContent = '';
  const ft = document.getElementById(`ft-${qid}`)?.value?.trim();
  if (ft) obState.freeTexts[qid] = ft;
  const ans = obState.answers[qid];
  const hasFree = ft && ft.length > 2;
  if (!ans && !(q.multiSelect && ans?.length) && !hasFree) {
    if (errEl) errEl.textContent = 'Please select an option or describe your situation below.';
    return;
  }
  if (ft && LS.get('fig_key') && (qid === 'q3' || qid === 'q4')) {
    const thinking = document.getElementById('llm-thinking');
    if (thinking) thinking.classList.add('show');
    try {
      const parsed = await callLLM(
        `You parse financial information from user free text. Return ONLY a JSON object with relevant fields extracted. For Q3 (income), return {"takeHome": number}. For Q4 (fixed costs), return {"fixedCosts": [{"name": string, "amount": number}]}. No other text.`,
        ft, true
      );
      obState.answers[`${qid}_parsed`] = parsed;
    } catch(e) {}
    if (thinking) thinking.classList.remove('show');
  }
  if (qid === 'q6') {
    await generateConfig();
  }
  advanceOB();
}

async function generateConfig() {
  if (!LS.get('fig_key')) {
    obState.llmConfig = buildRuleBasedConfig();
    return;
  }
  const thinking = document.getElementById('llm-thinking');
  if (thinking) thinking.classList.add('show');
  try {
    const prompt = `You are setting up a personal finance dashboard. Based on the user's answers, generate a config JSON.

User answers:
- Financial objective: ${obState.answers.q1} ${obState.freeTexts.q1||''}
- Timeline preference: ${obState.answers.q2}
- Monthly take-home: ${obState.answers.q3} ${obState.freeTexts.q3||''} ${obState.answers.q3_parsed ? JSON.stringify(obState.answers.q3_parsed) : ''}
- Fixed costs: ${obState.answers.q4} ${obState.freeTexts.q4||''} ${obState.answers.q4_parsed ? JSON.stringify(obState.answers.q4_parsed) : ''}
- Priority categories: ${(obState.answers.q5||[]).join(', ')} ${obState.freeTexts.q5||''}
- Track net worth: ${obState.answers.q6}

Return ONLY valid JSON:
{
  "goalName": "string",
  "goalType": "property|trip|debt|runway|general",
  "takeHome": number,
  "fixedTotal": number,
  "fixedBreakdown": [{"name": string, "amount": number}],
  "priorityCats": ["string"],
  "showNetWorth": boolean,
  "targetAmount": number or null,
  "targetYear": number or null,
  "timelineType": "fixed|open|suggest",
  "suggestedCategories": [{"name": string, "budget": number, "color": string, "priority": boolean}],
  "scenarios": [
    {"label": "Current pace", "monthlySavings": number, "description": "string"},
    {"label": "Optimised", "monthlySavings": number, "description": "string"},
    {"label": "Aggressive", "monthlySavings": number, "description": "string"}
  ]
}`;
    obState.llmConfig = await callLLM(prompt, 'Generate my dashboard config.', true);
  } catch(e) {
    obState.llmConfig = buildRuleBasedConfig();
  }
  if (thinking) thinking.classList.remove('show');
}

function buildRuleBasedConfig() {
  const incomeMap = {'<3000':2500,'3-5k':4000,'5-8k':6500,'8-12k':10000,'12-20k':16000,'>20k':22000};
  const takeHome = obState.answers.q3_parsed?.takeHome || incomeMap[obState.answers.q3] || 5000;
  const goalTypeMap = { property:'Buy a property', trip:'Save for a trip', debt:'Pay off debt', runway:'Build emergency fund', understand:'Understand my finances' };
  const goalType = obState.answers.q1 || 'general';
  const priorityCats = (obState.answers.q5||[]).map(v=>({food:'Food & Dining',transport:'Transport',housing:'Housing',travel:'Travel',health:'Health',education:'Education',savings:'Savings Rate'}[v]||v));
  const catSuggestions = [
    {name:'Food & Dining',budget:Math.round(takeHome*0.12),color:'#c4aaff',priority:priorityCats.includes('Food & Dining')},
    {name:'Groceries',budget:Math.round(takeHome*0.06),color:'#8ab4e8',priority:false},
    {name:'Transport',budget:Math.round(takeHome*0.07),color:'#7ec8a0',priority:priorityCats.includes('Transport')},
    {name:'Delivery / Takeout',budget:Math.round(takeHome*0.03),color:'#e07070',priority:false},
    {name:'Travel',budget:Math.round(takeHome*0.08),color:'#9580d0',priority:priorityCats.includes('Travel')},
    {name:'Shopping',budget:Math.round(takeHome*0.05),color:'#e8a070',priority:false},
    {name:'Health & Fitness',budget:Math.round(takeHome*0.03),color:'#70d4b4',priority:priorityCats.includes('Health')},
    {name:'Entertainment',budget:Math.round(takeHome*0.04),color:'#e8c48a',priority:false},
    {name:'Education',budget:Math.round(takeHome*0.03),color:'#b89ce0',priority:priorityCats.includes('Education')},
    {name:'Personal Care',budget:Math.round(takeHome*0.02),color:'#c8a0b0',priority:false},
    {name:'Other',budget:Math.round(takeHome*0.03),color:'#889080',priority:false},
  ];
  const totalBudget = catSuggestions.reduce((s,c)=>s+c.budget,0);
  const savings = takeHome - totalBudget;
  return {
    goalName: goalTypeMap[goalType] || 'Financial goal',
    goalType, takeHome, fixedTotal: 0, fixedBreakdown: [],
    priorityCats, showNetWorth: obState.answers.q6 === 'both',
    targetAmount: null, targetYear: null,
    timelineType: obState.answers.q2 || 'open',
    suggestedCategories: catSuggestions,
    scenarios: [
      {label:'Current pace', monthlySavings:savings, description:'Based on your budget targets'},
      {label:'Optimised',    monthlySavings:Math.round(savings*1.2), description:'Reduce top 2 variable categories by 15%'},
      {label:'Aggressive',   monthlySavings:Math.round(savings*1.5), description:'Full budget discipline'},
    ]
  };
}

function advanceOB() {
  obCurrentIdx = Math.min(obCurrentIdx + 1, obSteps.length - 1);
  renderOBStep();
}

function retreatOB() {
  obCurrentIdx = Math.max(obCurrentIdx - 1, 0);
  renderOBStep();
}

function updateProviderPlaceholder() {
  const p = document.getElementById('ob-provider')?.value;
  if (p && FINANCE_PROVIDERS[p]) document.getElementById('ob-key').placeholder = FINANCE_PROVIDERS[p].placeholder;
}

function saveAPIStep() {
  const provider = document.getElementById('ob-provider')?.value;
  const key = document.getElementById('ob-key')?.value?.trim();
  if (provider) LS.set('fig_provider', provider);
  if (key) LS.set('fig_key', key);
  advanceOB();
}

function skipAPIStep() { advanceOB(); }

function saveProfileStep() {
  obState.profile = {
    location: document.getElementById('prof-location')?.value?.trim(),
    age: parseInt(document.getElementById('prof-age')?.value) || null,
    employment: document.getElementById('prof-employment')?.value,
    income: document.getElementById('prof-income')?.value,
  };
  advanceOB();
}

function skipProfileStep() { advanceOB(); }

async function useTemplate(val) {
  obState.template = val;
  const templateConfigs = {
    property: { goalName:'Buy a property', goalType:'property', showNetWorth:true,  timelineType:'fixed' },
    debt:     { goalName:'Pay off debt',   goalType:'debt',     showNetWorth:true,  timelineType:'fixed' },
    runway:   { goalName:'Build runway',   goalType:'runway',   showNetWorth:false, timelineType:'open'  },
    general:  { goalName:'General tracking', goalType:'general', showNetWorth:true, timelineType:'open'  },
  };
  obState.llmConfig = { ...buildRuleBasedConfig(), ...templateConfigs[val] };
  obSteps = ['intro','q3','q4','api','profile','confirm'];
  obCurrentIdx = 1;
  renderOBStep();
}

async function launchDashboard() {
  const btn = document.getElementById('launch-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Building...'; }
  const config = obState.llmConfig || buildRuleBasedConfig();
  config.profile = obState.profile;
  config.createdAt = new Date().toISOString();
  config.estimatedFields = { takeHome:true, fixedTotal:true };
  await dbPut('config', config, 'main');
  buildDashboard(config, {});
}

async function buildDashboard(config, months) {
  dashConfig = config;
  dashMonths = months;
  document.getElementById('onboarding').style.display = 'none';
  document.getElementById('passcode-screen').style.display = 'none';
  document.getElementById('dashboard').style.display = 'block';

  const monthKeys = Object.keys(months).sort();
  const monthLabels = monthKeys.map(k => {
    const [y,m] = k.split('-');
    return ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][parseInt(m)-1]+' '+y.slice(2);
  });

  checkUploadReminder();
  document.getElementById('dash-subtitle').textContent = monthKeys.length
    ? `${monthLabels[0]} \u2013 ${monthLabels[monthLabels.length-1]} \u00B7 ${monthKeys.length} month${monthKeys.length>1?'s':''} of data`
    : 'No transactions uploaded yet \u00B7 estimates shown';
  document.getElementById('goal-pill').innerHTML = config.goalName + (config.targetYear ? `<br><span style="color:var(--muted)">target: ${config.targetYear}</span>` : '');

  renderFCF(config, months, monthKeys);
  if (monthKeys.length) {
    buildMonthTabs(monthKeys, monthLabels, config, months);
    renderBreakdown(config, months, monthKeys[monthKeys.length-1]);
    buildPie(config, months, monthKeys[monthKeys.length-1]);
    if (monthKeys.length >= 2) buildStack(config, months, monthKeys, monthLabels);
  } else {
    renderBreakdownBudgetOnly(config);
  }
  if (config.showNetWorth && config.netWorth) {
    document.getElementById('nw-divider').style.display = '';
    document.getElementById('nw-section').style.display = '';
    renderNetWorth(config);
  }
  renderGoal(config, months);
  buildManualRows(config);
  initChat(config);
  document.getElementById('reminder-days').value = LS.get('fig_reminder_days') || 30;
}

function renderFCF(config, months, monthKeys) {
  const takeHome = config.takeHome || 0;
  const fixedTotal = config.fixedTotal || 0;
  const avgDisc = monthKeys.length
    ? monthKeys.reduce((s,k)=>s+Object.values(months[k]).reduce((a,v)=>a+v,0),0)/monthKeys.length
    : (config.suggestedCategories||[]).reduce((s,c)=>s+c.budget,0);
  const savings = takeHome - fixedTotal - avgDisc;
  const isEst = config.estimatedFields;
  const fmt = (n) => '$'+Math.round(n||0).toLocaleString();
  document.getElementById('fcf-grid').innerHTML = `
    <div class="card gold">
      <div class="card-label">Take-home / month${isEst?.takeHome?'<span class="est-badge">est</span>':''}</div>
      <div class="card-value xl c-gold">${fmt(takeHome)}</div>
      <div class="card-sub">After tax, after retirement contributions</div>
    </div>
    <div class="card">
      <div class="card-label">Fixed costs${isEst?.fixedTotal?'<span class="est-badge">est</span>':''}</div>
      <div class="card-value c-warn">${fmt(fixedTotal)}</div>
      <div class="card-sub">${(config.fixedBreakdown||[]).slice(0,3).map(f=>`${f.name} ${fmt(f.amount)}`).join(' \u00B7 ') || 'Not set'}</div>
    </div>
    <div class="card">
      <div class="card-label">Avg discretionary${!monthKeys.length?'<span class="est-badge">est</span>':''}</div>
      <div class="card-value c-warn">${fmt(avgDisc)}</div>
      <div class="card-sub">${monthKeys.length?`${monthKeys.length}-month average`:'Based on your budgets'}</div>
    </div>
    <div class="card green">
      <div class="card-label">Monthly savings</div>
      <div class="card-value c-green">${fmt(Math.max(0,savings))}</div>
      <div class="card-sub">${fmt(takeHome)} \u2212 ${fmt(fixedTotal)} \u2212 ${fmt(avgDisc)}<br>~${fmt(savings*12)}/yr</div>
    </div>`;
}

function buildMonthTabs(monthKeys, monthLabels, config, months) {
  const tabs = document.getElementById('month-tabs');
  tabs.innerHTML = monthKeys.map((k,i)=>
    `<button class="m-tab ${i===monthKeys.length-1?'active':''}" data-key="${k}" onclick="selectMonth(this,'${k}')">${monthLabels[i]}</button>`
  ).join('');
}

function selectMonth(btn, key) {
  document.querySelectorAll('.m-tab').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderBreakdown(dashConfig, dashMonths, key);
  buildPie(dashConfig, dashMonths, key);
}

function renderBreakdown(config, months, selectedKey) {
  const cats = config.suggestedCategories || [];
  const data = months[selectedKey] || {};
  const allVals = cats.map(c=>Math.max(c.budget, data[c.name]||0));
  const maxVal = Math.max(...allVals, 1);
  document.getElementById('breakdown-desc').textContent =
    'Gold bar = budget \u00B7 Colored = actual \u00B7 Red = over budget \u00B7 Green = on track \u00B7 \u25CF = priority';
  const fmt = (n) => '$'+Math.round(n||0).toLocaleString();
  document.getElementById('budget-rows').innerHTML = cats.map(c => {
    const actual = data[c.name] || 0;
    const over = actual > c.budget && c.budget > 0 && actual > 0;
    const budgetPct = Math.min(c.budget/maxVal*100,100);
    const actualPct = Math.min(actual/maxVal*100,100);
    return `<div class="budget-row">
      <span class="b-label">${c.priority?'<span class="priority-dot"></span>':''} ${c.name}</span>
      <div class="b-bars">
        <div class="b-bar" style="width:${budgetPct}%;background:rgba(155,127,232,0.3)"></div>
        ${actual>0?`<div class="b-bar" style="width:${actualPct}%;background:${over?'var(--red)':'var(--green)'};opacity:0.85"></div>`:''}
      </div>
      <span class="b-amounts">
        <span style="color:var(--muted)">budget ${fmt(c.budget)}</span>
        ${actual>0?` · <span style="color:${over?'var(--red)':'var(--green)'}">${fmt(actual)}</span>`:''}
      </span>
    </div>`;
  }).join('');
}

function renderBreakdownBudgetOnly(config) {
  const cats = config.suggestedCategories || [];
  const maxBudget = Math.max(...cats.map(c=>c.budget),1);
  const fmt = (n) => '$'+Math.round(n||0).toLocaleString();
  document.getElementById('breakdown-desc').textContent = 'Budget targets shown. Upload transactions to see actuals.';
  document.getElementById('budget-rows').innerHTML = cats.map(c => {
    const pct = Math.min(c.budget/maxBudget*100,100);
    return `<div class="budget-row">
      <span class="b-label">${c.priority?'<span class="priority-dot"></span>':''} ${c.name} <span class="est-badge">est</span></span>
      <div class="b-bars"><div class="b-bar" style="width:${pct}%;background:${c.color};opacity:0.5"></div></div>
      <span class="b-amounts"><span style="color:var(--muted)">${fmt(c.budget)}</span></span>
    </div>`;
  }).join('');
}

function buildPie(config, months, key) {
  const cats = config.suggestedCategories || [];
  const data = cats.map(c=>(months[key]||{})[c.name]||0);
  const nonZero = cats.filter((_,i)=>data[i]>0);
  const nzData = data.filter(v=>v>0);
  if (!nonZero.length) return;
  if (charts.pie) charts.pie.destroy();
  charts.pie = new Chart(document.getElementById('pie-chart'), {
    type:'doughnut',
    data:{labels:nonZero.map(c=>c.name),datasets:[{data:nzData,backgroundColor:nonZero.map(c=>c.color),borderColor:'#12121a',borderWidth:3,hoverOffset:8}]},
    options:{plugins:{legend:{position:'right',labels:{color:'#8a8aa0',font:{family:'DM Mono',size:9},boxWidth:8,padding:8}},tooltip:{callbacks:{label:ctx=>` $${Number(ctx.raw).toLocaleString()}/mo`}}},cutout:'60%'}
  });
}

function buildStack(config, months, monthKeys, monthLabels) {
  const cats = config.suggestedCategories || [];
  document.getElementById('stack-empty').style.display = 'none';
  document.getElementById('stack-chart').style.display = '';
  if (charts.stack) charts.stack.destroy();
  charts.stack = new Chart(document.getElementById('stack-chart'), {
    type:'bar',
    data:{
      labels:monthLabels,
      datasets:cats.map(c=>({label:c.name,data:monthKeys.map(k=>(months[k]||{})[c.name]||0),backgroundColor:c.color+'cc',borderColor:c.color,borderWidth:1}))
    },
    options:{
      scales:{
        x:{stacked:true,ticks:{color:'#6b6880',font:{family:'DM Mono',size:9}},grid:{color:'#252535'}},
        y:{stacked:true,ticks:{color:'#6b6880',font:{family:'DM Mono',size:10},callback:v=>'$'+Math.round(v/1000)+'k'},grid:{color:'#252535'}}
      },
      plugins:{legend:{labels:{color:'#8a8aa0',font:{family:'DM Mono',size:9},boxWidth:8,padding:6}},tooltip:{callbacks:{label:ctx=>` ${ctx.dataset.label}: $${Math.round(ctx.raw).toLocaleString()}`}}}
    }
  });
}

function renderGoal(config, months) {
  const monthKeys = Object.keys(months).sort();
  const avgSavings = monthKeys.length
    ? (config.takeHome||0) - (config.fixedTotal||0) - monthKeys.reduce((s,k)=>s+Object.values(months[k]).reduce((a,v)=>a+v,0),0)/monthKeys.length
    : config.scenarios?.[0]?.monthlySavings || 0;
  const fmt = (n) => '$'+Math.round(n||0).toLocaleString();
  const fmtK = (n) => n>=1e6?'$'+(n/1e6).toFixed(1)+'M':n>=1e3?'$'+Math.round(n/1000)+'k':fmt(n);

  document.getElementById('goal-section-title').textContent = config.goalName || 'Goal Progress';
  const scenarios = config.scenarios || [];
  document.getElementById('scenario-grid').innerHTML = scenarios.map((s,i)=>`
    <div class="scenario-card ${i===0?'active':''}">
      <div class="scenario-label">${s.label}</div>
      <div class="scenario-rate">${fmt(s.monthlySavings)}<span style="font-size:0.7rem;color:var(--muted)">/mo</span></div>
      ${config.targetAmount ? `<div class="scenario-eta">${s.monthlySavings>0?Math.ceil(((config.targetAmount||0)-(config.goalSaved||0))/(s.monthlySavings*12)*10)/10+' yrs':'—'}</div>` : ''}
      <div class="scenario-desc">${s.description||''}</div>
    </div>`).join('');
  const remaining = (config.targetAmount||0) - (config.goalSaved||0);
  const yearsAtPace = avgSavings > 0 && remaining > 0 ? remaining/(avgSavings*12) : null;
  const pct = config.targetAmount ? Math.min(100,Math.round((config.goalSaved||0)/config.targetAmount*100)) : 0;
  document.getElementById('goal-details').innerHTML = config.targetAmount ? `
    <div class="card-label">Target</div>
    <div style="font-family:'Fraunces',serif;font-size:1.6rem;color:var(--accent2);margin-bottom:4px">${fmt(config.targetAmount)}</div>
    ${config.targetYear?`<div style="font-size:0.65rem;color:var(--muted);margin-bottom:20px">by ${config.targetYear}</div>`:''}
    <div class="card-label">Progress</div>
    <div class="progress-track"><div class="progress-fill-bar" style="width:${pct}%;background:var(--green)"></div></div>
    <div style="font-size:0.63rem;color:var(--muted);margin-top:4px;margin-bottom:20px">${fmt(config.goalSaved||0)} saved \u00B7 ${pct}%</div>
    ${yearsAtPace?`<div style="font-size:0.82rem;color:var(--green)">At current pace: ${yearsAtPace.toFixed(1)} years</div>`:'<div style="font-size:0.78rem;color:var(--muted)">Upload transactions to see your pace.</div>'}
  ` : `<div class="empty-state" style="padding:20px;text-align:left"><div>No target set.</div><div style="margin-top:8px;font-size:0.72rem">Chat with Fig: "Set my goal to $200,000 by 2029"</div></div>`;
  if (charts.savings) charts.savings.destroy();
  const years = Array.from({length:10},(_,i)=>i);
  const balances = years.map(y=>Math.round((config.goalSaved||0)+avgSavings*12*y));
  charts.savings = new Chart(document.getElementById('savings-chart'), {
    type:'line',
    data:{
      labels:years.map(y=>String(new Date().getFullYear()+y)),
      datasets:[
        {label:'Savings',data:balances,borderColor:'var(--accent)',backgroundColor:'rgba(155,127,232,0.1)',borderWidth:2,pointRadius:0,fill:true,tension:0.4},
        ...(config.targetAmount?[{label:'Goal',data:years.map(()=>config.targetAmount),borderColor:'rgba(126,200,160,0.4)',borderDash:[5,3],borderWidth:1,pointRadius:0,fill:false}]:[])
      ]
    },
    options:{scales:{x:{ticks:{color:'#6b6880',font:{family:'DM Mono',size:9},maxTicksLimit:5},grid:{color:'#252535'}},y:{ticks:{color:'#6b6880',font:{family:'DM Mono',size:9},callback:v=>fmtK(v)},grid:{color:'#252535'}}},plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>' '+fmtK(ctx.raw)}}}}
  });
}

function renderNetWorth(config) {
  const nw = config.netWorth || {};
  const assets = (nw.retirement||0)+(nw.savings||0)+(nw.invest||0)+(nw.property||0)+(nw.otherAsset||0);
  const liabs = (nw.cc||0)+(nw.studentLoans||0)+(nw.mortgage||0)+(nw.otherDebt||0);
  const total = assets - liabs;
  const fmt = (n) => '$'+Math.round(n||0).toLocaleString();
  document.getElementById('nw-card').innerHTML = `
    <div class="card-label">Total net worth</div>
    <div class="card-value xl ${total>=0?'c-green':'c-red'}" style="margin-bottom:14px">${fmt(total)}</div>
    <div style="font-size:0.58rem;letter-spacing:0.12em;text-transform:uppercase;color:var(--muted);margin-bottom:5px">Assets</div>
    ${[['Retirement',nw.retirement,'gold'],['Savings',nw.savings,'green'],['Investments',nw.invest,'green'],['Property',nw.property,'green']].filter(([,v])=>v>0).map(([l,v,c])=>`<div class="nw-row"><span class="nw-label">${l}</span><span class="nw-val ${c}">${fmt(v)}</span></div>`).join('')}
    <div style="font-size:0.58rem;letter-spacing:0.12em;text-transform:uppercase;color:var(--muted);margin:12px 0 5px">Liabilities</div>
    ${[['Credit card',nw.cc],['Student loans',nw.studentLoans],['Mortgage',nw.mortgage],['Other debt',nw.otherDebt]].filter(([,v])=>v>0).map(([l,v])=>`<div class="nw-row"><span class="nw-label">${l}</span><span class="nw-val red">\u2212${fmt(v)}</span></div>`).join('')||'<div class="nw-row"><span class="nw-label" style="color:var(--green)">No liabilities</span></div>'}
  `;
  const ret = config.retirement || {};
  const startBal = nw.retirement || 0;
  const years = Array.from({length:Math.max(1,(ret.targetAge||65)-(ret.age||30)+1)},(_,i)=>i);
  const balances = years.map(y=>{let b=startBal;for(let i=0;i<y;i++)b=b*(1+(ret.returnRate||0.07))+(ret.contrib||0);return Math.round(b);});
  document.getElementById('ret-card').innerHTML = `<div class="card-label" style="margin-bottom:12px">Retirement projection \u00B7 ${Math.round((ret.returnRate||0.07)*100)}% avg return</div><canvas id="ret-chart"></canvas>`;
  if (charts.ret) charts.ret.destroy();
  charts.ret = new Chart(document.getElementById('ret-chart'), {
    type:'line',
    data:{labels:years.map(y=>y===0?'Now':`Age ${(ret.age||30)+y}`),datasets:[{label:'401(k)',data:balances,borderColor:'#c4aaff',backgroundColor:'rgba(155,127,232,0.1)',borderWidth:2,pointRadius:0,fill:true,tension:0.4}]},
    options:{scales:{x:{ticks:{color:'#6b6880',font:{family:'DM Mono',size:9},maxTicksLimit:7},grid:{color:'#252535'}},y:{ticks:{color:'#6b6880',font:{family:'DM Mono',size:10},callback:v=>fmtK(v)},grid:{color:'#252535'}}},plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>' '+fmtK(ctx.raw)}}}}
  });
}

function guessCat(desc, cats) {
  const u = desc.toUpperCase();
  for (const cat of cats) {
    const words = cat.name.toUpperCase().replace(/[&\/]/g,' ').split(/\s+/);
    if (words.some(w=>w.length>3&&u.includes(w))) return cat.name;
  }
  if (/UBER EATS|DOORDASH|GRUBHUB|POSTMATES|FANTUAN|SEAMLESS/.test(u)) return 'Delivery / Takeout';
  if (/UBER|LYFT|WAYMO|TAXI|CLIPPER|TRANSIT|CALTRAIN|MUNI/.test(u)) return 'Transport';
  if (/ITALKI|DUOLINGO|COURSERA|UDEMY|SKILLSHARE|BRILLIANT/.test(u)) return 'Education';
  if (/HOTEL|AIRBNB|VRBO|EXPEDIA|BOOKING|DELTA|UNITED AIRLINES|SOUTHWEST|AMERICAN AIR/.test(u)) return 'Travel';
  if (/TRADER JOE|SAFEWAY|WHOLE FOODS|KROGER|COSTCO|WALMART GROCERY|SPROUTS/.test(u)) return 'Groceries';
  if (/RESTAURANT|CAFE|COFFEE|STARBUCKS|MCDONALD|CHIPOTLE|PIZZA|TACO|SUSHI|RAMEN|BAR /.test(u)) return 'Food & Dining';
  if (/BARBER|SALON|SPA|CVS|WALGREEN|RITE AID/.test(u)) return 'Personal Care';
  if (/AMAZON|BESTBUY|APPLE STORE|TARGET|NORDSTROM|ZARA|H\&M/.test(u)) return 'Shopping';
  if (/NETFLIX|SPOTIFY|HULU|DISNEY|APPLE\.COM|GOOGLE ONE|YOUTUBE/.test(u)) return 'Entertainment';
  if (/GYM|FITNESS|YOGA|PILATES|PELOTON|PLANET FITNESS/.test(u)) return 'Health & Fitness';
  return 'Other';
}

function checkUploadReminder() {
  const days = LS.get('fig_reminder_days') || 30;
  const last = LS.get('fig_last_upload');
  const dismissed = LS.get('fig_banner_dismissed');
  if (!last) { showBanner(`Upload your first month of transactions to see real data.`); return; }
  const daysSince = (Date.now() - new Date(last).getTime()) / 86400000;
  const daysSinceDismiss = dismissed ? (Date.now() - new Date(dismissed).getTime()) / 86400000 : Infinity;
  if (daysSince >= days && daysSinceDismiss > 3) showBanner(`It's been ${Math.round(daysSince)} days since your last upload.`);
}

function showBanner(text) {
  const el = document.getElementById('upload-banner');
  el.classList.remove('hidden');
  document.getElementById('banner-text').textContent = '\u{1F4C5} ' + text;
}

function dismissBanner() {
  document.getElementById('upload-banner').classList.add('hidden');
  LS.set('fig_banner_dismissed', new Date().toISOString());
}

function scrollToUpload() {
  dismissBanner();
  document.getElementById('drop-zone').scrollIntoView({behavior:'smooth'});
}

function saveReminderDays() {
  LS.set('fig_reminder_days', parseInt(document.getElementById('reminder-days').value)||30);
}

function initChat(config) {
  const greeting = `Hi! I'm Fig. I can answer questions about your finances, update your config, and help you understand your numbers. What would you like to know?`;
  if (chatHistory.length === 0) {
    chatHistory = [{role:'assistant', content:greeting}];
    renderChat();
  }
  const suggestions = [
    'How am I tracking against my goal?',
    'Where am I overspending?',
    'What would happen if I cut food spending by $200?',
    'Update my take-home to...',
  ];
  document.getElementById('chat-suggested').innerHTML = suggestions.map(s=>
    `<button class="sug-btn" onclick="fillSuggestion(this)">${s}</button>`
  ).join('');
}

function fillSuggestion(btn) {
  document.getElementById('chat-input').value = btn.textContent;
  document.getElementById('chat-input').focus();
}

function toggleChat() {
  const panel = document.getElementById('chat-panel');
  panel.classList.toggle('open');
  document.getElementById('chat-toggle-btn').classList.toggle('active');
}

function chatKeydown(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); }
}

function renderChat() {
  const container = document.getElementById('chat-messages');
  const msgs = chatHistory.filter(m => m.role !== 'system');
  container.innerHTML = msgs.map(m=>`<div class="chat-msg ${m.role}">${m.content.replace(/\n/g,'<br>')}</div>`).join('');
  container.scrollTop = container.scrollHeight;
}

async function sendChat() {
  const input = document.getElementById('chat-input');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';
  chatHistory.push({role:'user', content:text});
  renderChat();
  const btn = document.getElementById('chat-send-btn');
  btn.disabled = true;
  document.getElementById('chat-thinking').classList.add('show');
  const key = LS.get('fig_key');
  if (!key) {
    chatHistory.push({role:'assistant', content:'No API key connected. Open Settings and add your key to use the chat panel.'});
    renderChat();
    btn.disabled = false;
    document.getElementById('chat-thinking').classList.remove('show');
    return;
  }
  const monthKeys = Object.keys(dashMonths).sort();
  const avgByCategory = {};
  dashConfig.suggestedCategories.forEach(c=>{
    const avg = monthKeys.length ? monthKeys.reduce((s,k)=>s+(dashMonths[k]?.[c.name]||0),0)/monthKeys.length : c.budget;
    avgByCategory[c.name] = Math.round(avg);
  });
  const context = {
    config: { goalName:dashConfig.goalName, takeHome:dashConfig.takeHome, fixedTotal:dashConfig.fixedTotal, targetAmount:dashConfig.targetAmount, targetYear:dashConfig.targetYear, showNetWorth:dashConfig.showNetWorth },
    monthsOfData: monthKeys.length,
    averageMonthlySpend: avgByCategory,
    goalSaved: dashConfig.goalSaved || 0,
  };
  const systemPrompt = `You are Fig, a personal finance assistant. You have access to the user's financial summary data below. You never see raw transaction descriptions or personally identifying information.

User's financial context:
${JSON.stringify(context, null, 2)}

If the user asks you to update a value (e.g. "update my take-home to $11,000"), respond with the answer AND include a JSON block like:
<config_update>{"takeHome": 11000}</config_update>

Be concise, specific to their data, and practical.`;
  try {
    const response = await callLLM(systemPrompt, text);
    const updateMatch = response.match(/<config_update>([\s\S]*?)<\/config_update>/);
    if (updateMatch) {
      try {
        const updates = JSON.parse(updateMatch[1]);
        Object.assign(dashConfig, updates);
        await dbPut('config', dashConfig, 'main');
        buildDashboard(dashConfig, dashMonths);
      } catch(e) {}
    }
    const cleanResponse = response.replace(/<config_update>[\s\S]*?<\/config_update>/g, '').trim();
    chatHistory.push({role:'assistant', content:cleanResponse});
    await dbPut('chat', {role:'assistant', content:cleanResponse, ts:Date.now()});
  } catch(e) {
    chatHistory.push({role:'assistant', content:'Something went wrong. Check your API key and try again.'});
  }
  renderChat();
  btn.disabled = false;
  document.getElementById('chat-thinking').classList.remove('show');
}

function handlePasscode() {
  const val = document.getElementById('pc-input').value;
  const stored = LS.get('fig_passcode');
  if (!stored) {
    if (val) LS.set('fig_passcode', val);
    showOnboardingOrDashboard();
  } else {
    if (val !== stored) {
      document.getElementById('pc-input').style.borderColor = 'var(--red)';
      return;
    }
    showOnboardingOrDashboard();
  }
}

const handleFile = async function(file) {
  if (!file || !dashConfig) return;
  const isCsv = file.name.endsWith('.csv');
  const reader = new FileReader();
  reader.onload = async e => {
    let rows = [];
    if (isCsv) {
      const lines = e.target.result.split('\n');
      const header = lines[0].split(',').map(h=>h.trim().replace(/"/g,'').toLowerCase());
      const di = header.findIndex(h=>h.includes('description')||h.includes('merchant')||h.includes('payee')||h.includes('name'));
      const ai = header.findIndex(h=>h.includes('amount')||h.includes('debit')||h.includes('charge'));
      if (di===-1||ai===-1) { alert('Couldn\'t find Description and Amount columns. Check your CSV format.'); return; }
      lines.slice(1).forEach(l=>{
        if (!l.trim()) return;
        const cols = l.match(/("([^"]*)"|[^,]*)/g).map(v=>v.replace(/^"|"$/g,'').trim());
        const amt = parseFloat(cols[ai]);
        if (isNaN(amt)||amt<=0) return;
        rows.push({desc:cols[di]||'',amt});
      });
    } else {
      const wb = XLSX.read(e.target.result,{type:'array'});
      const sn = wb.SheetNames.find(n=>n.toLowerCase().includes('transaction'))||wb.SheetNames[0];
      const raw = XLSX.utils.sheet_to_json(wb.Sheets[sn],{header:1});
      let hi = -1;
      for (let i=0;i<raw.length;i++) { if(raw[i]&&raw[i].some(c=>String(c).trim().toLowerCase()==='date')){hi=i;break;} }
      if (hi===-1) { alert('Couldn\'t find transaction data — expected a row with "Date" as a header.'); return; }
      const headers = raw[hi].map(h=>String(h).trim().toLowerCase());
      const ai = headers.findIndex(h=>h.includes('amount')||h.includes('debit'));
      const di = headers.findIndex(h=>h.includes('description')||h.includes('merchant')||h.includes('payee'));
      raw.slice(hi+1).forEach(r=>{ const amt=parseFloat(r[ai]); if(isNaN(amt)||amt<=0)return; rows.push({desc:String(r[di]||''),amt}); });
    }
    const spend = {};
    dashConfig.suggestedCategories.forEach(c=>spend[c.name]=0);
    let total = 0;
    rows.forEach(({desc,amt})=>{
      const cat = guessCat(desc, dashConfig.suggestedCategories);
      spend[cat] = (spend[cat]||0) + amt;
      total += amt;
    });
    const month = parseInt(document.getElementById('upload-month').value);
    const year = document.getElementById('upload-year').value;
    const key = `${year}-${String(month).padStart(2,'0')}`;
    const merge = document.getElementById('merge-toggle').checked;
    const existing = await dbGet('months', key) || {};
    const finalSpend = merge
      ? Object.fromEntries(dashConfig.suggestedCategories.map(c=>[c.name,(existing[c.name]||0)+(spend[c.name]||0)]))
      : spend;
    await dbPut('months', finalSpend, key);
    dashMonths[key] = finalSpend;
    if (dashConfig.estimatedFields) {
      delete dashConfig.estimatedFields.takeHome;
      delete dashConfig.estimatedFields.fixedTotal;
      await dbPut('config', dashConfig, 'main');
    }
    LS.set('fig_last_upload', new Date().toISOString());
    const allKeys = Object.keys(dashMonths).sort();
    const allLabels = allKeys.map(k=>{const[y,m]=k.split('-');return['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][parseInt(m)-1]+' '+y.slice(2);});
    buildDashboard(dashConfig, dashMonths);
    const avgBudget = dashConfig.suggestedCategories.reduce((s,c)=>s+c.budget,0);
    const diff = total - avgBudget;
    const vt = document.getElementById('verdict-title');
    vt.textContent = diff < 0 ? `\u2191 Under budget \u2014 ${fmtK(diff)} below targets` : `\u2193 Over budget \u2014 ${fmtK(diff)} above targets`;
    vt.style.color = diff < 0 ? 'var(--green)' : 'var(--red)';
    const items = dashConfig.suggestedCategories.map(c=>({name:c.name,d:(finalSpend[c.name]||0)-c.budget,actual:finalSpend[c.name]||0})).filter(x=>Math.abs(x.d)>=20).sort((a,b)=>Math.abs(b.d)-Math.abs(a.d));
    const fmt = (n) => '$'+Math.round(n||0).toLocaleString();
    document.getElementById('verdict-list').innerHTML = items.map(({name,d,actual})=>`<li class="${d<0?'good':'bad'}">${name}: ${fmt(actual)} (${d<0?'\u2212':'+'}${fmt(Math.abs(d))} vs budget)</li>`).join('');
    document.getElementById('verdict').classList.add('show');
    const mName = ['January','February','March','April','May','June','July','August','September','October','November','December'][month-1];
    alert(`Imported ${mName} ${year}: ${rows.length} transactions, ${fmt(total)} total.`);
  };
  if (isCsv) reader.readAsText(file);
  else reader.readAsArrayBuffer(file);
};

function fmt(n) { return '$' + Math.round(n||0).toLocaleString(); }
function fmtK(n) { return n>=1e6?'$'+(n/1e6).toFixed(1)+'M':n>=1e3?'$'+Math.round(n/1000)+'k':fmt(n); }

function resetApp() {
  if (confirm('Reset Fig and start over? All data will be cleared.')) {
    indexedDB.deleteDatabase(DB_NAME);
    localStorage.clear();
    window.location.reload();
  }
}

async function showOnboardingOrDashboard() {
  const config = await dbGet('config', 'main');
  if (config && config.createdAt) {
    const monthKeys = await dbGetAllKeys('months');
    const months = {};
    for (const k of monthKeys) months[k] = await dbGet('months', k);
    try { chatHistory = await dbGetAll('chat'); } catch (e) { chatHistory = []; }
    try {
      buildDashboard(config, months);
    } catch (e) {
      console.error('Dashboard render failed:', e);
      document.getElementById('dashboard').style.display = 'none';
      document.getElementById('onboarding').style.display = 'none';
      const al = document.getElementById('app-loading');
      if (al) {
        al.style.display = 'flex';
        al.style.color = 'var(--red)';
        document.getElementById('app-loading-text').innerHTML =
          'Couldn\u2019t render the dashboard.<br><span style="color:var(--muted);font-size:0.7rem;font-weight:normal">' +
          (e && e.message || e) + '</span><br><span style="color:var(--muted);font-size:0.7rem;font-weight:normal">Click Reset above to start fresh.</span>';
      }
    }
  } else {
    document.getElementById('onboarding').style.display = 'block';
    renderOBStep();
  }
}

async function initFinance() {
  db = await openDB();
  document.getElementById('app-loading').style.display = 'none';
  const passcode = LS.get('fig_passcode');
  if (passcode !== null) {
    document.getElementById('passcode-screen').style.display = 'block';
    document.getElementById('pc-input').focus();
  } else {
    await showOnboardingOrDashboard();
  }
  const now = new Date();
  const monthEl = document.getElementById('upload-month');
  const yearEl = document.getElementById('upload-year');
  if (monthEl) monthEl.value = now.getMonth() + 1;
  if (yearEl) yearEl.value = now.getFullYear();
}

function buildManualRows(config) {
  const cats = config.suggestedCategories || [];
  const wrap = document.getElementById('manual-rows');
  if (!wrap) return;
  wrap.innerHTML = cats.map(c=>`
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <div style="width:8px;height:8px;border-radius:50%;background:${c.color};flex-shrink:0"></div>
      <span style="flex:1;font-size:0.75rem;color:var(--muted)">${c.name}</span>
      <input type="number" id="manual-${c.name.replace(/[^a-z]/gi,'_')}" placeholder="${c.budget}" min="0"
        style="width:90px;text-align:right;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:5px 8px;color:var(--text);font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;font-size:0.75rem;outline:none">
    </div>`).join('');
}

async function saveManual() {
  const config = dashConfig;
  const month = parseInt(document.getElementById('upload-month').value);
  const year = document.getElementById('upload-year').value;
  const key = `${year}-${String(month).padStart(2,'0')}`;
  const entry = {};
  config.suggestedCategories.forEach(c=>{
    const val = parseFloat(document.getElementById(`manual-${c.name.replace(/[^a-z]/gi,'_')}`)?.value);
    if (!isNaN(val) && val > 0) entry[c.name] = val;
  });
  await dbPut('months', entry, key);
  dashMonths[key] = entry;
  LS.set('fig_last_upload', new Date().toISOString());
  buildDashboard(config, dashMonths);
  const mName = ['January','February','March','April','May','June','July','August','September','October','November','December'][month-1];
  alert(`Saved ${mName} ${year}`);
}

window.handleFile = handleFile;
window.initFinance = initFinance;

// Auto-initialize on load
if (document.readyState === 'complete' || document.readyState === 'interactive') {
  initFinance().catch(function(e) {
    console.error('Finance auto-init error:', e.message || e);
    var el = document.getElementById('app-loading');
    if (el) { el.style.display = 'flex'; el.style.color = 'var(--red)'; el.innerHTML = 'Error: ' + (e.message||e); }
  });
} else {
  document.addEventListener('DOMContentLoaded', function() {
    initFinance().catch(function(e) {
      console.error('Finance auto-init error:', e.message || e);
      var el = document.getElementById('app-loading');
      if (el) { el.style.display = 'flex'; el.style.color = 'var(--red)'; el.innerHTML = 'Error: ' + (e.message||e); }
    });
  });
}
window.figEmergencyReset = resetApp;
window.selectChoice = selectChoice;
window.selectTemplate = selectTemplate;
window.advanceQuestion = advanceQuestion;
window.advanceOB = advanceOB;
window.retreatOB = retreatOB;
window.updateProviderPlaceholder = updateProviderPlaceholder;
window.saveAPIStep = saveAPIStep;
window.skipAPIStep = skipAPIStep;
window.saveProfileStep = saveProfileStep;
window.skipProfileStep = skipProfileStep;
window.useTemplate = useTemplate;
window.launchDashboard = launchDashboard;
window.selectMonth = selectMonth;
window.toggleChat = toggleChat;
window.chatKeydown = chatKeydown;
window.fillSuggestion = fillSuggestion;
window.sendChat = sendChat;
window.handlePasscode = handlePasscode;
window.scrollToUpload = scrollToUpload;
window.dismissBanner = dismissBanner;
window.saveReminderDays = saveReminderDays;
window.resetApp = resetApp;
window.saveManual = saveManual;
