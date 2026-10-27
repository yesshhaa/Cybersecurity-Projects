/**
 * app.js — Improve 2.0 UI: state, import, fix plan, verification, reports
 */

(function () {
  'use strict';

  const { detectAndParse } = window.ImproveParsers;
  const E = window.ImproveEngine;
  const { KEV_SEED } = window.ImprovePlaybooks;

  const STORE_KEY = 'improve2.state.v1';
  const KEV_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
  const STATUS_LABEL = { open: 'Open', fixed: 'Fix applied', verified: 'Verified', accepted: 'Risk accepted' };

  const CONNECTORS = [
    { name: 'Nessus / Tenable', fmt: 'CSV', how: 'Scans → open a scan → Report → CSV (keep default columns).', cmd: '' },
    { name: 'OpenVAS / Greenbone', fmt: 'CSV', how: 'Scans → Reports → pick a report → download as "CSV Results".', cmd: '' },
    { name: 'OWASP ZAP', fmt: 'JSON', how: 'Baseline scan of a website with Docker:', cmd: 'docker run --rm -v "$PWD":/zap/wrk -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://your-site.example -J zap.json' },
    { name: 'Trivy', fmt: 'JSON', how: 'Container images, repos and IaC — vulnerabilities, misconfigs and secrets:', cmd: 'trivy image --scanners vuln,secret,misconfig --format json -o trivy.json your-image:tag' },
    { name: 'Semgrep', fmt: 'SARIF', how: 'Static analysis of your source code:', cmd: 'semgrep scan --config auto --sarif -o semgrep.sarif' },
    { name: 'GitHub code scanning / CodeQL', fmt: 'SARIF', how: 'Download the SARIF artifact from the CodeQL workflow run, or via the API:', cmd: 'gh api repos/OWNER/REPO/code-scanning/analyses/ID -H "Accept: application/sarif+json" > codeql.sarif' },
    { name: 'Anything else', fmt: 'CSV / JSON', how: 'Any spreadsheet with columns such as title, severity, host, port, cve, cwe, description, solution.', cmd: 'title,severity,host,port,cve,description\n"MFA not enforced for admins",high,m365.example.com,,,"3 admin accounts without MFA"' }
  ];

  /* ── state ───────────────────────────────────────── */

  let state = load();
  let plan = [];
  let drawerKey = null;
  let showDone = false;
  let tuneOpen = false;

  function emptyState() { return { findings: {}, status: {}, assets: {}, imports: [], kev: null }; }

  function load() {
    try {
      const raw = localStorage.getItem(STORE_KEY);
      if (raw) return Object.assign(emptyState(), JSON.parse(raw));
    } catch (e) { /* private mode / blocked storage: run in-memory */ }
    return emptyState();
  }

  function save() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(state)); }
    catch (e) { toast('Could not save to this browser — changes last until you close the tab.'); }
  }

  function kevSet() { return new Set(KEV_SEED.concat(state.kev ? state.kev.list : [])); }

  function assetKey(f) { return f.asset || 'unknown asset'; }

  function assetInfo(f) {
    const saved = state.assets[assetKey(f)];
    return {
      exposure: (saved && saved.exposure) || E.inferExposure(f.asset, f),
      critical: !!(saved && saved.critical)
    };
  }

  function statusOf(id) { return state.status[id] || { status: 'open', checks: {}, note: '', history: [] }; }

  function setStatus(id, status, text) {
    const s = Object.assign({ checks: {}, note: '', history: [] }, state.status[id]);
    s.status = status;
    s.history = (s.history || []).concat({ at: new Date().toISOString(), text: text || STATUS_LABEL[status] });
    state.status[id] = s;
  }

  function recompute() {
    plan = E.buildPlan(Object.values(state.findings), { assetInfo, kev: kevSet() });
  }

  /* ── import ──────────────────────────────────────── */

  function fid(f) {
    const key = [f.tool, f.title, f.asset, f.port, f.url, f.file, f.line, f.pkg, f.cve.join(',')].join('|').toLowerCase();
    let h = 0x811c9dc5;
    for (let i = 0; i < key.length; i++) { h ^= key.charCodeAt(i); h = Math.imul(h, 0x01000193); }
    return 'f' + (h >>> 0).toString(36);
  }

  function importText(text, name) {
    let parsed;
    try { parsed = detectAndParse(text, name); }
    catch (e) { toast(`${name}: ${e.message}`); return null; }

    const now = new Date().toISOString();
    const incoming = new Map();
    parsed.findings.forEach((f) => { incoming.set(fid(f), f); });

    // Re-scan comparison: same tool + same asset seen again → anything missing was fixed,
    // anything we thought was fixed but is still reported reopens.
    const covered = new Set([...incoming.values()].map((f) => f.tool + '|' + assetKey(f)));
    // Hosts this tool scanned before but that have zero findings now: either clean or out of scope — ask.
    const tools = new Set([...incoming.values()].map((f) => f.tool));
    const missing = [...new Set(Object.values(state.findings)
      .filter((f) => tools.has(f.tool) && !covered.has(f.tool + '|' + assetKey(f)) && statusOf(f.id).status !== 'verified')
      .map((f) => f.tool + '|' + assetKey(f)))];
    if (missing.length && confirm(`"${name}" has no findings for ${missing.length} asset(s) seen in earlier scans from the same tool:\n\n${missing.map((m) => m.split('|')[1]).join('\n')}\n\nDid this scan include them? OK = yes, their missing findings count as fixed. Cancel = they were not scanned.`)) {
      missing.forEach((m) => covered.add(m));
    }
    let autoVerified = 0, reopened = 0, newCount = 0;

    Object.entries(state.findings).forEach(([id, f]) => {
      if (!covered.has(f.tool + '|' + assetKey(f))) return;
      const st = statusOf(id).status;
      if (!incoming.has(id)) {
        if (st === 'fixed') { setStatus(id, 'verified', `Verified — absent from re-scan "${name}"`); autoVerified++; }
        else if (st === 'open') { setStatus(id, 'fixed', `Not reported in re-scan "${name}" — run the checks to confirm`); }
      } else if (st === 'fixed' || st === 'verified') {
        setStatus(id, 'open', `Reopened — still reported in re-scan "${name}"`);
        reopened++;
      }
    });

    incoming.forEach((f, id) => {
      const prev = state.findings[id];
      if (!prev) newCount++;
      state.findings[id] = Object.assign(f, { id, firstSeen: prev ? prev.firstSeen : now, lastSeen: now });
    });

    state.imports.unshift({ name, format: parsed.format, count: incoming.size, newCount, at: now });
    state.imports = state.imports.slice(0, 50);
    save();

    let msg = `${name}: ${incoming.size} findings from ${parsed.format}`;
    if (newCount !== incoming.size) msg += ` (${newCount} new)`;
    if (autoVerified) msg += ` · ${autoVerified} fix${autoVerified > 1 ? 'es' : ''} confirmed by re-scan`;
    if (reopened) msg += ` · ${reopened} reopened`;
    return msg;
  }

  async function importFiles(files) {
    const msgs = [];
    for (const file of files) {
      if (file.size > 25 * 1024 * 1024) { toast(`${file.name} is over 25 MB — export a filtered report.`); continue; }
      const m = importText(await file.text(), file.name);
      if (m) msgs.push(m);
    }
    afterImport(msgs);
  }

  async function loadSample(which) {
    const names = which === 'all' ? ['nessus-office-network.csv', 'zap-storefront.json', 'trivy-storefront-image.json'] : [which];
    const msgs = [];
    for (const n of names) {
      try {
        const res = await fetch('samples/' + n);
        if (!res.ok) throw new Error(res.status);
        const m = importText(await res.text(), n);
        if (m) msgs.push(m);
      } catch (e) { toast(`Could not load sample ${n}. If you opened the file directly, serve the folder over http.`); }
    }
    afterImport(msgs);
  }

  function afterImport(msgs) {
    if (!msgs.length) return;
    toast(msgs.join('  •  '), 6000);
    go('plan');
  }

  /* ── helpers ─────────────────────────────────────── */

  const $ = (sel, root) => (root || document).querySelector(sel);

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  /** Escape, then render `inline code`. */
  function rich(s) { return esc(s).replace(/`([^`]+)`/g, '<code>$1</code>'); }

  function sevPill(s) { return `<span class="pill sev sev-${esc(s)}">${esc(s)}</span>`; }

  function cmdBlock(cmd) {
    return `<div class="cmd"><code>${esc(cmd)}</code><button class="copy" data-copy="${esc(cmd)}" type="button">copy</button></div>`;
  }

  function fmtDate(iso) {
    try { return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); } catch (e) { return iso; }
  }

  function groupProgress(g) {
    const c = { open: 0, fixed: 0, verified: 0, accepted: 0 };
    g.items.forEach((i) => { c[statusOf(i.f.id).status]++; });
    c.total = g.items.length;
    c.done = c.verified + c.accepted;
    return c;
  }

  function progressBar(c, cls) {
    const pv = c.total ? ((c.verified + c.accepted) / c.total) * 100 : 0;
    const pf = c.total ? (c.fixed / c.total) * 100 : 0;
    return `<div class="progress ${cls || ''}" role="img" aria-label="${c.done} of ${c.total} verified"><span class="p-verified" style="width:${pv}%"></span><span class="p-fixed" style="width:${pf}%"></span></div>`;
  }

  let toastTimer;
  function toast(msg, ms) {
    const t = $('#toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), ms || 3500);
  }

  function download(name, content, type) {
    const blob = new Blob([content], { type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }

  /* ── routing ─────────────────────────────────────── */

  function go(view) {
    if (!['plan', 'findings', 'import', 'report'].includes(view)) view = Object.keys(state.findings).length ? 'plan' : 'import';
    if (location.hash !== '#' + view) history.replaceState(null, '', '#' + view);
    document.querySelectorAll('.tab').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.view === view)));
    document.querySelectorAll('.view').forEach((v) => { v.hidden = v.id !== 'view-' + view; });
    render(view);
    window.scrollTo(0, 0);
  }

  function currentView() { return (document.querySelector('.tab[aria-selected="true"]') || {}).dataset?.view || 'import'; }

  function render(view) {
    recompute();
    const openActions = plan.filter((g) => groupProgress(g).done < g.items.length).length;
    $('#count-plan').textContent = openActions;
    $('#count-findings').textContent = Object.keys(state.findings).length;
    view = view || currentView();
    if (view === 'plan') renderPlan();
    if (view === 'findings') renderFindings();
    if (view === 'import') renderImport();
    if (view === 'report') renderReport();
    if (drawerKey) renderDrawer();
  }

  /* ── import view ─────────────────────────────────── */

  function renderImport() {
    $('#connectors').innerHTML = CONNECTORS.map((c) => `
      <div class="connector">
        <header><h3>${esc(c.name)}</h3><span class="pill">${esc(c.fmt)}</span></header>
        <p>${esc(c.how)}</p>
        ${c.cmd ? cmdBlock(c.cmd) : ''}
      </div>`).join('');

    $('#imports').innerHTML = state.imports.length ? `
      <h2>Import history</h2>
      <ul class="import-list">
        ${state.imports.map((i) => `<li><span class="pill">${esc(i.format)}</span><span class="grow">${esc(i.name)}</span><span class="muted">${i.count} findings${i.newCount != null && i.newCount !== i.count ? `, ${i.newCount} new` : ''}</span><span class="muted">${esc(fmtDate(i.at))}</span></li>`).join('')}
      </ul>` : '';
  }

  /* ── plan view ───────────────────────────────────── */

  function renderPlan() {
    const root = $('#plan-root');
    const all = Object.values(state.findings);
    if (!all.length) {
      root.innerHTML = `<div class="empty card"><h2>No findings yet</h2><p>Import a report from Nessus, ZAP, Trivy, Semgrep or a spreadsheet — or load a sample to see how it works.</p><button class="btn btn-primary" data-go="import">Import findings</button></div>`;
      return;
    }

    const counts = { open: 0, fixed: 0, verified: 0, accepted: 0 };
    all.forEach((f) => { counts[statusOf(f.id).status]++; });
    const total = all.length;
    const nowOpen = plan.filter((g) => g.bucket === 'now' && groupProgress(g).done < g.items.length).length;
    const assets = [...new Set(all.map(assetKey))];

    const assetRows = assets.sort().map((a) => {
      const sample = all.find((f) => assetKey(f) === a);
      const info = assetInfo(sample);
      const n = all.filter((f) => assetKey(f) === a).length;
      return `<tr>
        <td class="mono">${esc(a)}</td>
        <td>${n}</td>
        <td><select data-asset="${esc(a)}" data-field="exposure" aria-label="Exposure for ${esc(a)}">
          ${['internet', 'internal', 'code'].map((x) => `<option value="${x}" ${info.exposure === x ? 'selected' : ''}>${{ internet: 'Internet-facing', internal: 'Internal only', code: 'Code / image' }[x]}</option>`).join('')}
        </select></td>
        <td><label class="row" style="gap:6px"><input type="checkbox" data-asset="${esc(a)}" data-field="critical" ${info.critical ? 'checked' : ''}/> Business-critical</label></td>
      </tr>`;
    }).join('');

    const buckets = E.BUCKETS.map((b) => {
      const groups = plan.filter((g) => g.bucket === b.id && (showDone || groupProgress(g).done < g.items.length));
      if (!groups.length) return '';
      return `<section class="bucket bucket-${b.id}">
        <div class="bucket-head"><h2>${esc(b.label)}</h2><span class="pill">${groups.length}</span><span class="blurb">${esc(b.blurb)}</span></div>
        <div class="actions">${groups.map(actionCard).join('')}</div>
      </section>`;
    }).join('');

    const allDone = plan.every((g) => groupProgress(g).done === g.items.length);

    root.innerHTML = `
      <div class="plan-head">
        <div>
          <div class="eyebrow">Fix plan</div>
          <h1 style="font-size:32px">${plan.length} fix action${plan.length === 1 ? '' : 's'} across ${assets.length} asset${assets.length === 1 ? '' : 's'}</h1>
          <p class="lede" style="font-size:15px">Ranked by real-world risk, not just severity. Work top to bottom — each action ends with a check that proves it's done.</p>
        </div>
        <label class="row" style="gap:8px;font-size:14px"><input type="checkbox" id="show-done" ${showDone ? 'checked' : ''}/> Show completed</label>
      </div>
      <div class="stats">
        <div class="stat hot"><div class="num">${nowOpen}</div><div class="lbl">Actions to fix today</div></div>
        <div class="stat"><div class="num">${counts.open}</div><div class="lbl">Open findings</div></div>
        <div class="stat"><div class="num">${counts.fixed}</div><div class="lbl">Fixed, awaiting verification</div></div>
        <div class="stat ok"><div class="num">${counts.verified}</div><div class="lbl">Verified fixed${counts.accepted ? ` · ${counts.accepted} accepted` : ''}</div></div>
      </div>
      ${progressBar(Object.assign({ total, done: counts.verified + counts.accepted }, counts))}
      <div class="progress-legend"><span><i style="background:var(--ok)"></i>Verified ${Math.round(((counts.verified + counts.accepted) / total) * 100)}%</span><span><i style="background:var(--sev-medium)"></i>Fix applied ${Math.round((counts.fixed / total) * 100)}%</span><span><i style="background:var(--surface-3)"></i>Open</span></div>

      <details class="tune card" id="tune" style="padding:16px 20px" ${tuneOpen ? 'open' : ''}>
        <summary>Tune the ranking <span>— tell us which assets face the internet and which matter most</span></summary>
        <table class="asset-table"><thead><tr><th>Asset</th><th>Findings</th><th>Exposure</th><th>Importance</th></tr></thead><tbody>${assetRows}</tbody></table>
      </details>

      ${buckets || ''}
      ${allDone ? `<div class="empty card" style="margin-top:30px"><h2>Everything is verified 🎉</h2><p>Re-run your scanners on a schedule and import the results here — new issues will slot into the plan and fixed ones will confirm themselves.</p></div>` : ''}
    `;
  }

  function actionCard(g) {
    const c = groupProgress(g);
    const done = c.done === c.total;
    const topReason = g.reasons.filter((r) => r.hot)[0] || g.reasons.slice().sort((a, b) => b.pts - a.pts)[0];
    const assetsTxt = g.assets.length === 1 ? g.assets[0] : `${g.assets.length} assets`;
    return `<button class="action ${done ? 'done' : ''}" data-group="${esc(g.key)}" type="button">
      <div class="score s-${g.bucket}" title="Priority score">${g.score}</div>
      <div>
        <div class="action-title">${esc(g.title)}</div>
        <div class="action-meta">
          ${sevPill(g.severity)}
          <span class="pill">${esc(g.pb.category)}</span>
          ${g.kev ? '<span class="pill pill-hot">Exploited in the wild</span>' : ''}
          <span class="pill">${esc(assetsTxt)}</span>
        </div>
        <div class="action-why">Why here: ${esc(topReason ? topReason.text : '')}</div>
      </div>
      <div class="action-side">
        <span>${done ? '<span class="pill pill-ok">Done</span>' : `~${esc(g.pb.effort)}`}</span>
        <span>${c.done}/${c.total} verified</span>
        ${progressBar(c, 'mini-progress')}
      </div>
    </button>`;
  }

  /* ── findings view ───────────────────────────────── */

  function renderFindings() {
    const q = $('#f-search').value.trim().toLowerCase();
    const sev = $('#f-sev').value;
    const st = $('#f-status').value;
    const rows = [];
    plan.forEach((g) => g.items.forEach((i) => rows.push({ g, i })));
    rows.sort((a, b) => b.i.score - a.i.score);
    const filtered = rows.filter(({ g, i }) => {
      const f = i.f;
      if (sev && f.severity !== sev) return false;
      if (st && statusOf(f.id).status !== st) return false;
      if (!q) return true;
      return [f.title, f.asset, f.tool, f.cve.join(' '), f.pkg, f.url, f.file, g.title].join(' ').toLowerCase().includes(q);
    });

    if (!rows.length) {
      $('#findings-root').innerHTML = `<div class="empty card"><h2>No findings yet</h2><p>Import a report to get started.</p><button class="btn btn-primary" data-go="import">Import findings</button></div>`;
      return;
    }

    $('#findings-root').innerHTML = `<div class="table-wrap"><table class="findings-table">
      <thead><tr><th>Score</th><th>Finding</th><th>Asset</th><th>Severity</th><th>Fix action</th><th>Status</th></tr></thead>
      <tbody>${filtered.map(({ g, i }) => {
        const f = i.f;
        const s = statusOf(f.id).status;
        return `<tr data-group="${esc(g.key)}" data-focus="${esc(f.id)}" tabindex="0">
          <td><span class="score s-${E.BUCKETS.find((b) => i.score >= b.min).id}" style="width:38px;height:38px;font-size:14px">${i.score}</span></td>
          <td><div class="t">${esc(f.title)}</div><div class="sub">${esc(f.tool)}${f.cve.length ? ' · ' + esc(f.cve.join(', ')) : ''}${f.pkg ? ' · ' + esc(f.pkg + ' ' + f.installed) : ''}</div></td>
          <td class="mono">${esc(f.asset || '—')}${f.port ? ':' + esc(f.port) : ''}${f.file && !f.port ? '<br>' + esc(f.file) + (f.line ? ':' + esc(f.line) : '') : ''}</td>
          <td>${sevPill(f.severity)}</td>
          <td class="sub">${esc(g.title)}</td>
          <td>${statusPill(s)}</td>
        </tr>`;
      }).join('')}</tbody></table></div>
      <p class="muted" style="font-size:13px;margin-top:10px">${filtered.length} of ${rows.length} findings</p>`;
  }

  function statusPill(s) {
    const cls = { open: '', fixed: 'pill-warn', verified: 'pill-ok', accepted: '' }[s];
    return `<span class="pill ${cls}">${esc(STATUS_LABEL[s])}</span>`;
  }

  /* ── drawer ──────────────────────────────────────── */

  let lastFocus = null;

  function openDrawer(key, focusId) {
    lastFocus = document.activeElement;
    drawerKey = key;
    renderDrawer();
    $('#drawer').classList.add('open');
    $('#drawer').setAttribute('aria-hidden', 'false');
    $('#scrim').classList.add('open');
    document.body.style.overflow = 'hidden';
    $('#drawer-body').scrollTop = 0;
    if (focusId) {
      const el = document.getElementById('t-' + focusId);
      if (el) { el.scrollIntoView({ block: 'start' }); el.classList.add('flash'); }
    }
    $('.drawer-close').focus();
  }

  function closeDrawer() {
    drawerKey = null;
    $('#drawer').classList.remove('open');
    $('#drawer').setAttribute('aria-hidden', 'true');
    $('#scrim').classList.remove('open');
    document.body.style.overflow = '';
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  function renderDrawer() {
    const g = plan.find((x) => x.key === drawerKey);
    if (!g) { closeDrawer(); return; }
    const pb = g.pb;
    const first = g.items[0];
    const c = groupProgress(g);
    const t0 = first.tokens;

    $('#drawer-head').innerHTML = `
      <div class="score s-${g.bucket}" style="flex:none">${g.score}</div>
      <div style="min-width:0">
        <div class="action-meta">${sevPill(g.severity)}<span class="pill">${esc(pb.category)}</span>${g.kev ? '<span class="pill pill-hot">Exploited in the wild</span>' : ''}<span class="pill">Fix effort: ${esc(pb.effort)}</span></div>
        <h2 id="drawer-title">${esc(g.title)}</h2>
        <div class="muted" style="font-size:13px">${c.done}/${c.total} verified · ${esc(E.BUCKETS.find((b) => b.id === g.bucket).label)}</div>
      </div>
      <button class="drawer-close" type="button" aria-label="Close">×</button>`;

    const fixHtml = pb.fix.map((grp) => `
      <div class="fix-group">
        <h4>${esc(grp.label)}</h4>
        <ol>${grp.steps.map((s) => `<li>${rich(E.fill(s, t0))}</li>`).join('')}</ol>
      </div>`).join('');

    const targets = g.items.map((it) => targetCard(it, pb)).join('');

    const toolInfo = g.items.slice(0, 1).map((it) => {
      const f = it.f;
      const rowsKv = [
        ['Tool', f.tool], ['Rule / plugin', f.rule], ['CVE', f.cve.join(', ')], ['CWE', f.cwe.map((x) => 'CWE-' + x).join(', ')],
        ['CVSS', f.cvss], ['Package', f.pkg && `${f.pkg} ${f.installed}${f.fixed ? ' → ' + f.fixed : ''}`]
      ].filter(([, v]) => v !== '' && v != null);
      return `<details class="tool-says">
        <summary>What the scanner said (${esc(f.tool)})</summary>
        <dl class="kv">${rowsKv.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>
        ${f.title !== g.title ? `<pre>${esc(f.title)}</pre>` : ''}
        ${f.description ? `<pre>${esc(f.description)}</pre>` : ''}
        ${f.solution ? `<pre><b>Suggested solution:</b> ${esc(f.solution)}</pre>` : ''}
        ${f.cve[0] ? `<p style="margin-top:8px"><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.cve[0])}" target="_blank" rel="noopener noreferrer">${esc(f.cve[0])} on NVD ↗</a></p>` : ''}
      </details>`;
    }).join('');

    const total = g.reasons.reduce((s, r) => s + r.pts, 0);

    $('#drawer-body').innerHTML = `
      <div class="section">
        <h3>What it means</h3>
        <p class="lead">${rich(E.fill(pb.means, t0))}</p>
      </div>
      <div class="section">
        <div class="explain-grid">
          <div class="card"><h4>How it could be exploited</h4><p>${rich(E.fill(pb.exploit, t0))}</p></div>
          <div class="card impact"><h4>If it happens</h4><p>${rich(E.fill(pb.impact, t0))}</p></div>
        </div>
      </div>
      <div class="section">
        <h3>Why it ranks here</h3>
        <ul class="why-list">${g.reasons.map((r) => `<li class="${r.hot ? 'hot' : ''}"><span class="pts">+${r.pts}</span><span>${esc(r.text)}</span></li>`).join('')}</ul>
        <div class="why-total">Score ${g.score}/100${total > g.score ? ' (capped)' : ''}${g.items.length > 1 ? ` — highest of ${g.items.length} affected items` : ''}. Change asset exposure or importance under "Tune the ranking".</div>
      </div>
      <div class="section">
        <h3>How to fix it</h3>
        ${fixHtml}
      </div>
      <div class="section">
        <h3>Confirm the fix ${g.items.length > 1 ? `<span class="pill">${g.items.length} targets</span>` : ''}</h3>
        <p style="font-size:14px">Run each check, compare with the expected result, and tick it. "Verified" unlocks once every check passes. Importing a fresh scan also confirms fixes automatically.</p>
        ${targets}
      </div>
      <div class="section">${toolInfo}</div>
    `;
  }

  function targetCard(it, pb) {
    const f = it.f;
    const st = statusOf(f.id);
    const checks = pb.verify.map((v, idx) => {
      const id = `chk-${f.id}-${idx}`;
      return `<div class="check">
        <input type="checkbox" id="${id}" data-check="${esc(f.id)}" data-idx="${idx}" ${st.checks && st.checks[idx] ? 'checked' : ''} />
        <div>
          <label class="check-title" for="${id}">${esc(E.fill(v.check, it.tokens))}</label>
          ${cmdBlock(E.fill(v.cmd, it.tokens))}
          <div class="check-expect"><b>Pass when:</b> ${rich(E.fill(v.expect, it.tokens))}</div>
        </div>
      </div>`;
    }).join('');
    const allChecked = pb.verify.every((v, idx) => st.checks && st.checks[idx]);
    const loc = f.url || [f.asset, f.port].filter(Boolean).join(':') || f.file;
    const where = [f.file && f.file !== loc ? f.file + (f.line ? ':' + f.line : '') : '', f.pkg ? `${f.pkg} ${f.installed}` : ''].filter(Boolean).join(' · ');

    return `<div class="target" id="t-${esc(f.id)}">
      <div class="target-head">
        <span class="asset">${esc(loc || 'unknown asset')}</span>
        ${where ? `<span class="muted" style="font-size:12.5px">${esc(where)}</span>` : ''}
        <span class="grow"></span>
        ${sevPill(f.severity)} ${statusPill(st.status)}
      </div>
      <div class="target-body">
        ${checks}
        <div class="status-row">
          ${['open', 'fixed', 'verified', 'accepted'].map((s) => `<button type="button" class="status-btn st-${s}" data-status="${s}" data-id="${esc(f.id)}" aria-pressed="${st.status === s}" ${s === 'verified' && !allChecked && st.status !== 'verified' ? 'disabled title="Tick every check first"' : ''}>${STATUS_LABEL[s]}</button>`).join('')}
          ${!allChecked && st.status !== 'verified' ? '<span class="status-hint">Verified unlocks when all checks pass</span>' : ''}
        </div>
        <textarea class="note-input" data-note="${esc(f.id)}" placeholder="Evidence / notes — e.g. command output, change ticket, who fixed it. Required to accept risk." aria-label="Evidence notes">${esc(st.note || '')}</textarea>
        ${st.history && st.history.length ? `<div class="history">${st.history.slice(-4).reverse().map((h) => `<div>${esc(fmtDate(h.at))} — ${esc(h.text)}</div>`).join('')}</div>` : ''}
      </div>
    </div>`;
  }

  /* ── report view ─────────────────────────────────── */

  function buildMarkdown() {
    const all = Object.values(state.findings);
    const counts = { open: 0, fixed: 0, verified: 0, accepted: 0 };
    all.forEach((f) => { counts[statusOf(f.id).status]++; });
    const L = [];
    L.push('# Security Fix Plan — Improve 2.0', '');
    L.push(`Generated ${new Date().toLocaleString()} · ${all.length} findings · ${plan.length} fix actions`, '');
    L.push(`**Progress:** ${counts.verified} verified · ${counts.fixed} fixed awaiting verification · ${counts.accepted} risk-accepted · ${counts.open} open`, '');
    E.BUCKETS.forEach((b) => {
      const gs = plan.filter((g) => g.bucket === b.id);
      if (!gs.length) return;
      L.push(`## ${b.label}`, '', `_${b.blurb}_`, '');
      gs.forEach((g, n) => {
        const c = groupProgress(g);
        const t0 = g.items[0].tokens;
        L.push(`### ${n + 1}. ${g.title} — score ${g.score}`, '');
        L.push(`- **Severity:** ${g.severity} · **Effort:** ${g.pb.effort} · **Status:** ${c.done}/${c.total} verified${g.kev ? ' · **Exploited in the wild (CISA KEV)**' : ''}`);
        L.push(`- **Affected:** ${g.assets.join(', ')}`);
        L.push(`- **Why it's here:** ${g.reasons.filter((r) => r.pts >= 10).map((r) => r.text).join('; ')}`, '');
        L.push(`**What it means:** ${E.fill(g.pb.means, t0)}`, '');
        L.push(`**How it could be exploited:** ${E.fill(g.pb.exploit, t0)}`, '');
        L.push('**Fix:**');
        g.pb.fix.forEach((grp) => { L.push(`- _${grp.label}_`); grp.steps.forEach((s) => L.push(`  - ${E.fill(s, t0)}`)); });
        L.push('', '**Confirm the fix:**');
        g.items.forEach((it) => {
          const st = statusOf(it.f.id);
          L.push(`- \`${it.f.url || [it.f.asset, it.f.port].filter(Boolean).join(':') || it.f.file || 'asset'}\` — ${STATUS_LABEL[st.status]}${st.note ? ` — _${st.note.replace(/\n/g, ' ')}_` : ''}`);
          g.pb.verify.forEach((v, idx) => L.push(`  - [${st.checks && st.checks[idx] ? 'x' : ' '}] ${E.fill(v.check, it.tokens)}: \`${E.fill(v.cmd, it.tokens)}\` → ${E.fill(v.expect, it.tokens)}`));
        });
        L.push('');
      });
    });
    return L.join('\n');
  }

  function buildCsv() {
    const cols = ['priority_score', 'bucket', 'fix_action', 'severity', 'title', 'asset', 'port', 'url', 'file', 'package', 'cve', 'tool', 'status', 'evidence', 'last_updated'];
    const q = (v) => {
      let s = String(v == null ? '' : v);
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // neutralise spreadsheet formula injection
      return '"' + s.replace(/"/g, '""') + '"';
    };
    const lines = [cols.join(',')];
    plan.forEach((g) => g.items.forEach((it) => {
      const f = it.f;
      const st = statusOf(f.id);
      const last = st.history && st.history.length ? st.history[st.history.length - 1].at : '';
      lines.push([it.score, g.bucket, g.title, f.severity, f.title, f.asset, f.port, f.url, f.file, f.pkg && `${f.pkg} ${f.installed}`, f.cve.join(' '), f.tool, STATUS_LABEL[st.status], st.note, last].map(q).join(','));
    }));
    return lines.join('\n');
  }

  function renderReport() {
    const has = Object.keys(state.findings).length > 0;
    const kevInfo = state.kev ? `${state.kev.list.length.toLocaleString()} CVEs, updated ${fmtDate(state.kev.updated)}` : `built-in list of ${KEV_SEED.length} high-profile CVEs`;
    $('#report-root').innerHTML = `
      <div class="eyebrow">Share &amp; keep records</div>
      <h1 style="font-size:32px">Report</h1>
      <p class="lede" style="font-size:15px">Hand the plan to whoever does the work, or keep it as evidence for auditors and cyber-insurance questionnaires.</p>
      <div class="report-grid">
        <div class="card"><h3>Action plan (Markdown)</h3><p>Ranked actions with explanations, fix steps, verification checks and their current status.</p>
          <div class="row"><button class="btn btn-primary btn-sm" data-act="md" ${has ? '' : 'disabled'}>Download .md</button><button class="btn btn-sm" data-act="copy-md" ${has ? '' : 'disabled'}>Copy</button><button class="btn btn-sm" data-act="print" ${has ? '' : 'disabled'}>Print</button></div></div>
        <div class="card"><h3>Tracker export (CSV)</h3><p>One row per finding with score, status and evidence — paste into a spreadsheet or ticketing tool.</p>
          <div class="row"><button class="btn btn-sm" data-act="csv" ${has ? '' : 'disabled'}>Download .csv</button></div></div>
        <div class="card"><h3>Exploited-vulnerability data</h3><p>Findings with CVEs on CISA's Known Exploited Vulnerabilities catalog jump the queue. Currently using: ${esc(kevInfo)}.</p>
          <div class="row"><button class="btn btn-sm" data-act="kev">Update from CISA KEV</button></div></div>
        <div class="card"><h3>Backup &amp; reset</h3><p>Progress is stored in this browser only. Export a backup to move it to another device.</p>
          <div class="row"><button class="btn btn-sm" data-act="backup" ${has ? '' : 'disabled'}>Export backup</button>
          <label class="btn btn-sm" for="restore-input">Restore backup</label><input type="file" id="restore-input" class="sr-only" accept=".json,application/json" />
          <button class="btn btn-sm btn-danger" data-act="clear" ${has ? '' : 'disabled'}>Clear all data</button></div></div>
      </div>
      ${has ? `<div class="report-preview"><h2>Preview</h2><pre id="md-preview"></pre></div>` : ''}
    `;
    if (has) $('#md-preview').textContent = buildMarkdown();
  }

  async function refreshKev() {
    toast('Downloading CISA KEV catalog…');
    try {
      const res = await fetch(KEV_URL, { cache: 'no-store' });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      const list = (data.vulnerabilities || []).map((v) => v.cveID).filter(Boolean);
      if (!list.length) throw new Error('empty catalog');
      state.kev = { list, updated: new Date().toISOString(), version: data.catalogVersion || '' };
      save();
      render();
      toast(`KEV updated: ${list.length.toLocaleString()} known-exploited CVEs.`);
    } catch (e) {
      toast('Could not reach the KEV catalog (' + e.message + '). Using the built-in list.');
    }
  }

  /* ── events ──────────────────────────────────────── */

  document.addEventListener('click', (e) => {
    const t = e.target;

    const tab = t.closest('.tab');
    if (tab) { go(tab.dataset.view); return; }

    const goBtn = t.closest('[data-go]');
    if (goBtn) { go(goBtn.dataset.go); return; }

    const copy = t.closest('.copy');
    if (copy) {
      const text = copy.dataset.copy;
      (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject())
        .then(() => { copy.textContent = 'copied'; setTimeout(() => { copy.textContent = 'copy'; }, 1200); })
        .catch(() => toast('Copy failed — select the text manually.'));
      return;
    }

    const sample = t.closest('[data-sample]');
    if (sample) { loadSample(sample.dataset.sample); return; }

    const grp = t.closest('[data-group]');
    if (grp) { openDrawer(grp.dataset.group, grp.dataset.focus); return; }

    if (t.closest('.drawer-close') || t.id === 'scrim') { closeDrawer(); return; }

    const sb = t.closest('.status-btn');
    if (sb && !sb.disabled) {
      const id = sb.dataset.id;
      const next = sb.dataset.status;
      const st = statusOf(id);
      if (next === st.status) return;
      if (next === 'accepted' && !(st.note || '').trim()) { toast('Write a reason in the notes box before accepting the risk.'); return; }
      let text = STATUS_LABEL[next];
      if (next === 'verified') {
        const g = plan.find((x) => x.key === drawerKey);
        text = `Verified — ${g ? g.pb.verify.length : ''} check(s) passed`;
      }
      if (next === 'accepted') text = 'Risk accepted: ' + st.note.trim().slice(0, 80);
      setStatus(id, next, text);
      save();
      const scroll = $('#drawer-body').scrollTop;
      render();
      $('#drawer-body').scrollTop = scroll;
      if (next === 'verified') toast('Nice — fix verified.');
      return;
    }

    const act = t.closest('[data-act]');
    if (act && !act.disabled) {
      const a = act.dataset.act;
      const stamp = new Date().toISOString().slice(0, 10);
      if (a === 'md') download(`fix-plan-${stamp}.md`, buildMarkdown(), 'text/markdown');
      if (a === 'copy-md') navigator.clipboard.writeText(buildMarkdown()).then(() => toast('Plan copied as Markdown.'), () => toast('Copy failed.'));
      if (a === 'print') printPlan();
      if (a === 'csv') download(`findings-${stamp}.csv`, buildCsv(), 'text/csv');
      if (a === 'kev') refreshKev();
      if (a === 'backup') download(`improve-backup-${stamp}.json`, JSON.stringify(state, null, 2), 'application/json');
      if (a === 'clear' && confirm('Delete all imported findings, progress and notes from this browser?')) {
        state = emptyState(); save(); toast('All data cleared.'); go('import');
      }
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && drawerKey) closeDrawer();
    if (e.key === 'Enter' && e.target.matches('tr[data-group]')) openDrawer(e.target.dataset.group, e.target.dataset.focus);
  });

  document.addEventListener('change', (e) => {
    const t = e.target;
    if (t.matches('[data-check]')) {
      const id = t.dataset.check;
      const st = Object.assign({ status: 'open', note: '', history: [] }, state.status[id]);
      st.checks = Object.assign({}, st.checks, { [t.dataset.idx]: t.checked });
      state.status[id] = st;
      save();
      const scroll = $('#drawer-body').scrollTop;
      renderDrawer();
      $('#drawer-body').scrollTop = scroll;
      return;
    }
    if (t.matches('[data-asset]')) {
      const a = t.dataset.asset;
      const sample = Object.values(state.findings).find((f) => assetKey(f) === a);
      const cur = Object.assign(assetInfo(sample), state.assets[a]);
      cur[t.dataset.field] = t.type === 'checkbox' ? t.checked : t.value;
      state.assets[a] = cur;
      save();
      render('plan');
      toast('Ranking updated.');
      return;
    }
    if (t.id === 'show-done') { showDone = t.checked; renderPlan(); return; }
    if (t.id === 'file-input' && t.files.length) { importFiles([...t.files]); t.value = ''; return; }
    if (t.id === 'restore-input' && t.files.length) {
      t.files[0].text().then((txt) => {
        const data = JSON.parse(txt);
        if (!data || typeof data.findings !== 'object') throw new Error('not an Improve backup');
        state = Object.assign(emptyState(), data);
        save();
        toast('Backup restored.');
        go('plan');
      }).catch((err) => toast('Restore failed: ' + err.message));
      t.value = '';
      return;
    }
    if (t.matches('#f-sev, #f-status')) renderFindings();
  });

  document.addEventListener('input', (e) => {
    const t = e.target;
    if (t.matches('[data-note]')) {
      const id = t.dataset.note;
      const st = Object.assign({ status: 'open', checks: {}, history: [] }, state.status[id]);
      st.note = t.value;
      state.status[id] = st;
      save();
    }
    if (t.id === 'f-search') renderFindings();
  });

  $('#paste-import').addEventListener('click', () => {
    const text = $('#paste-input').value;
    if (!text.trim()) { toast('Paste a report first.'); return; }
    const m = importText(text, 'Pasted report');
    if (m) { $('#paste-input').value = ''; afterImport([m]); }
  });

  const dz = $('#dropzone');
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('drag'); }));
  dz.addEventListener('drop', (e) => { if (e.dataTransfer.files.length) importFiles([...e.dataTransfer.files]); });
  // Avoid the browser navigating to a file dropped outside the zone
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => e.preventDefault());

  function printPlan() {
    const w = window.open('', '_blank');
    if (!w) { toast('Allow pop-ups to print.'); return; }
    w.document.title = 'Security Fix Plan';
    const pre = w.document.createElement('pre');
    pre.style.cssText = 'white-space:pre-wrap;font:12px/1.5 ui-monospace,Menlo,monospace;padding:24px';
    pre.textContent = buildMarkdown();
    w.document.body.appendChild(pre);
    w.focus();
    w.print();
  }

  document.addEventListener('toggle', (e) => { if (e.target.id === 'tune') tuneOpen = e.target.open; }, true);

  window.addEventListener('hashchange', () => go(location.hash.slice(1)));
  go(location.hash.slice(1));
})();
