/**
 * engine.js — Matching, prioritisation and fix-plan grouping
 *
 * Priority score (0–100) is transparent on purpose: every point comes with a
 * human-readable reason so the user can see *why* something is first.
 */

(function (global) {
  'use strict';

  const { PLAYBOOKS, GENERIC } = global.ImprovePlaybooks;
  const byId = Object.fromEntries(PLAYBOOKS.map((p) => [p.id, p]));
  byId.generic = GENERIC;

  const SEV_POINTS = { critical: 40, high: 30, medium: 18, low: 8, info: 2 };
  const EFFORT_POINTS = { minutes: 4, hours: 2, days: 0 };
  const DEFAULT_PORTS = { 'tls-weak': '443', 'tls-cert': '443', 'ssh-weak': '22', 'rdp-exposed': '3389', 'cleartext-service': '21' };

  const BUCKETS = [
    { id: 'now',   label: 'Fix today',      min: 70, blurb: 'Easily exploited and reachable. Drop other work.' },
    { id: 'week',  label: 'This week',      min: 50, blurb: 'Real risk — schedule before Friday.' },
    { id: 'month', label: 'This month',     min: 30, blurb: 'Hardening and lower-impact issues.' },
    { id: 'later', label: 'Backlog',        min: 0,  blurb: 'Informational or low impact. Batch these.' }
  ];

  /* ── matching ─────────────────────────────────────── */

  function matchPlaybook(f) {
    const title = f.title || '';
    const desc = (f.description || '') + ' ' + (f.solution || '');

    for (const p of PLAYBOOKS) if (p.match.cve && f.cve.some((c) => p.match.cve.includes(c))) return p;
    if (f.rule) for (const p of PLAYBOOKS) if (p.match.rule && p.match.rule.includes(String(f.rule))) return p;
    if (f.pkg && (f.cve.length || f.fixed)) return byId['vulnerable-package'];
    for (const p of PLAYBOOKS) if (p.match.cwe && f.cwe.some((c) => p.match.cwe.includes(c))) return p;
    for (const p of PLAYBOOKS) if (p.match.kw && p.match.kw.some((re) => re.test(title))) return p;
    for (const p of PLAYBOOKS) if (p.match.kw && p.match.kw.some((re) => re.test(desc))) return p;
    if (f.cve.length) return byId['vulnerable-package'];
    return GENERIC;
  }

  /* ── exposure inference ───────────────────────────── */

  function inferExposure(asset, finding) {
    const a = String(asset || '').toLowerCase();
    if (finding && (finding.file || finding.pkg) && !finding.url && !finding.port) return 'code';
    if (!a) return 'internal';
    if (/^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a)) return 'internal';
    if (/^(fc|fd)[0-9a-f]{2}:/.test(a) || a === '::1') return 'internal';
    if (/\.(local|lan|internal|corp|home|intranet|localdomain)$/.test(a) || !a.includes('.')) return 'internal';
    if (/[/:@]/.test(a) && !/^\d+\.\d+\.\d+\.\d+$/.test(a)) return 'code'; // image refs, repo paths
    return 'internet';
  }

  /* ── scoring ──────────────────────────────────────── */

  function score(f, pb, assetInfo, kev) {
    const reasons = [];
    let s = SEV_POINTS[f.severity] || 0;
    reasons.push({ pts: s, text: `${cap(f.severity)} severity from ${f.tool}` });

    const ex = pb.exploitability * 7;
    s += ex;
    reasons.push({ pts: ex, text: ['', 'Needs unusual conditions to exploit', 'Commonly abused by attackers', 'Trivial to exploit / mass-scanned'][pb.exploitability] });

    const kevHits = f.cve.filter((c) => kev.has(c));
    if (kevHits.length) {
      s += 20;
      reasons.push({ pts: 20, text: `Exploited in the wild (CISA KEV: ${kevHits.join(', ')})`, hot: true });
    }

    const exposure = assetInfo.exposure;
    const expPts = exposure === 'internet' ? 15 : exposure === 'internal' ? 6 : 4;
    s += expPts;
    reasons.push({ pts: expPts, text: { internet: 'Asset is internet-facing', internal: 'Asset is internal only', code: 'Lives in code / an image (ships wherever it is deployed)' }[exposure] });

    if (exposure === 'internet' && pb.exploitability === 3) {
      s += 10;
      reasons.push({ pts: 10, text: 'Internet-reachable AND easy to exploit', hot: true });
    } else if (f.severity === 'critical' && pb.exploitability === 3) {
      s += 10;
      reasons.push({ pts: 10, text: 'Critical AND easy to exploit', hot: true });
    }

    if (assetInfo.critical) {
      s += 10;
      reasons.push({ pts: 10, text: 'You marked this asset business-critical' });
    }

    const eff = EFFORT_POINTS[pb.effort] || 0;
    if (eff) {
      s += eff;
      reasons.push({ pts: eff, text: `Quick win — fix takes ${pb.effort}` });
    }

    if (f.severity === 'info') s = Math.min(s, 29);
    return { score: Math.min(100, Math.round(s)), reasons, kev: kevHits.length > 0 };
  }

  function bucketFor(scoreVal) {
    return BUCKETS.find((b) => scoreVal >= b.min).id;
  }

  /* ── templating ───────────────────────────────────── */

  function tokensFor(f, pb) {
    const host = f.asset && !/[/@]/.test(f.asset) ? f.asset.replace(/:\d+$/, '') : (f.url ? safeHost(f.url) : '');
    const port = f.port || DEFAULT_PORTS[pb.id] || (f.url && f.url.startsWith('http:') ? '80' : '443');
    const url = f.url || (host ? `https://${host}${port && port !== '443' ? ':' + port : ''}/` : '');
    const domain = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? host : host.split('.').slice(-2).join('.');
    return {
      host: host || '<host>',
      port,
      url: url || '<url>',
      domain: domain || '<your-domain>',
      pkg: f.pkg || '<package>',
      installed: f.installed || '',
      fixed: f.fixed || '<fixed version>',
      file: f.file || 'the affected code',
      line: f.line ? ':' + f.line : '',
      cve: f.cve[0] || 'the CVE'
    };
  }

  function fill(str, tokens) {
    return String(str).replace(/\{(\w+)\}/g, (m, k) => (k in tokens ? tokens[k] : m));
  }

  /* ── grouping into fix actions ────────────────────── */

  /**
   * One "fix action" = one playbook applied to one or more assets.
   * Vulnerable packages are grouped per package+fixed version (one upgrade fixes them all).
   */
  function buildPlan(findings, ctx) {
    const groups = new Map();
    findings.forEach((f) => {
      const pb = matchPlaybook(f);
      const assetInfo = ctx.assetInfo(f);
      const sc = score(f, pb, assetInfo, ctx.kev);
      let key = pb.id;
      if (pb.id === 'vulnerable-package') key += '|' + f.pkg + '|' + (f.fixed || f.cve.join(','));
      if (pb.id === 'generic') key += '|' + f.title.toLowerCase();
      if (!groups.has(key)) groups.set(key, { key, pb, items: [], score: 0, reasons: [], kev: false, severity: 'info' });
      const g = groups.get(key);
      g.items.push({ f, score: sc.score, reasons: sc.reasons, kev: sc.kev, tokens: tokensFor(f, pb) });
      if (sc.score > g.score) { g.score = sc.score; g.reasons = sc.reasons; }
      g.kev = g.kev || sc.kev;
      if (sevRank(f.severity) < sevRank(g.severity)) g.severity = f.severity;
    });

    const list = [...groups.values()].map((g) => {
      g.items.sort((a, b) => b.score - a.score);
      g.bucket = bucketFor(g.score);
      g.title = g.pb.id === 'vulnerable-package'
        ? `Upgrade ${g.items[0].f.pkg}${g.items[0].f.fixed ? ' to ' + g.items[0].f.fixed : ''}`
        : g.pb.id === 'generic' ? g.items[0].f.title : g.pb.title;
      g.assets = [...new Set(g.items.map((i) => i.f.asset || 'unknown asset'))];
      return g;
    });
    list.sort((a, b) => b.score - a.score || b.items.length - a.items.length);
    return list;
  }

  function sevRank(s) { return ['critical', 'high', 'medium', 'low', 'info'].indexOf(s); }
  function cap(s) { return s ? s[0].toUpperCase() + s.slice(1) : s; }
  function safeHost(u) { try { return new URL(u).hostname; } catch (e) { return ''; } }

  global.ImproveEngine = { matchPlaybook, inferExposure, score, buildPlan, fill, tokensFor, BUCKETS, sevRank, byId };
})(window);
