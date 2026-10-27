/**
 * parsers.js — Import findings from common security tools into one shape
 *
 * Supported:
 *   SARIF 2.1 (Semgrep, CodeQL, Trivy --format sarif, Snyk, Checkov …)
 *   Trivy JSON (image / fs / config)
 *   OWASP ZAP JSON report
 *   Nessus CSV export · OpenVAS / Greenbone CSV export
 *   Generic CSV or JSON (columns like title, severity, host, cve, cwe, port, description)
 *
 * Normalized finding:
 *   { tool, title, description, solution, severity, cvss, cve[], cwe[], rule,
 *     asset, port, url, file, line, pkg, installed, fixed }
 */

(function (global) {
  'use strict';

  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

  /* ── helpers ─────────────────────────────────────── */

  function normSeverity(value, cvss) {
    const v = String(value == null ? '' : value).trim().toLowerCase();
    if (SEVERITIES.includes(v)) return v;
    if (v === 'informational' || v === 'none' || v === 'note' || v === 'log') return 'info';
    if (v === 'moderate' || v === 'warning' || v === 'medium-high') return 'medium';
    if (v === 'error') return 'high';
    if (v === 'unknown' || v === '') {
      if (cvss != null && !isNaN(cvss)) return fromCvss(Number(cvss));
      return 'info';
    }
    if (!isNaN(Number(v))) return fromCvss(Number(v));
    return 'info';
  }

  function fromCvss(score) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    if (score > 0) return 'low';
    return 'info';
  }

  function extractCves(...texts) {
    const out = new Set();
    texts.join(' ').replace(/CVE-\d{4}-\d{4,7}/gi, (m) => { out.add(m.toUpperCase()); return m; });
    return [...out];
  }

  function extractCwes(...vals) {
    const out = new Set();
    vals.flat().forEach((v) => {
      if (v == null) return;
      String(v).replace(/(?:CWE[-_: ]?)?(\d{1,4})/gi, (m, n) => {
        if (/cwe/i.test(m) || /^\d{1,4}$/.test(String(v).trim())) out.add(Number(n));
        return m;
      });
    });
    out.delete(0);
    return [...out];
  }

  function stripHtml(s) {
    if (!s) return '';
    if (typeof DOMParser === 'undefined') return String(s).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim(); // Node (tests)
    // DOMParser documents are inert: no scripts or event handlers run
    const doc = new DOMParser().parseFromString(String(s).replace(/<\/p>\s*<p>/gi, '\n\n'), 'text/html');
    return (doc.body.textContent || '').trim();
  }

  function hostFromUrl(u) {
    try { return new URL(u).hostname; } catch (e) { return ''; }
  }

  function portFromUrl(u) {
    try {
      const x = new URL(u);
      return x.port || (x.protocol === 'https:' ? '443' : x.protocol === 'http:' ? '80' : '');
    } catch (e) { return ''; }
  }

  function base(partial) {
    return Object.assign({
      tool: 'Unknown', title: 'Untitled finding', description: '', solution: '',
      severity: 'info', cvss: null, cve: [], cwe: [], rule: '',
      asset: '', port: '', url: '', file: '', line: '', pkg: '', installed: '', fixed: ''
    }, partial);
  }

  /* ── CSV ─────────────────────────────────────────── */

  function parseCsv(text) {
    const rows = [];
    let row = [], field = '', i = 0, quoted = false;
    text = text.replace(/^﻿/, '');
    while (i < text.length) {
      const c = text[i];
      if (quoted) {
        if (c === '"') {
          if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
          quoted = false; i++; continue;
        }
        field += c; i++; continue;
      }
      if (c === '"') { quoted = true; i++; continue; }
      if (c === ',') { row.push(field); field = ''; i++; continue; }
      if (c === '\r') { i++; continue; }
      if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
      field += c; i++;
    }
    if (field !== '' || row.length) { row.push(field); rows.push(row); }
    const nonEmpty = rows.filter((r) => r.some((f) => f.trim() !== ''));
    if (!nonEmpty.length) return [];
    const headers = nonEmpty[0].map((h) => h.trim());
    return nonEmpty.slice(1).map((r) => {
      const o = {};
      headers.forEach((h, idx) => { o[h] = (r[idx] || '').trim(); });
      return o;
    });
  }

  /** Case-insensitive column lookup across candidate names. */
  function pick(obj, ...names) {
    const keys = Object.keys(obj);
    for (const n of names) {
      const k = keys.find((key) => key.toLowerCase().replace(/[\s_-]/g, '') === n.toLowerCase().replace(/[\s_-]/g, ''));
      if (k && obj[k] !== '' && obj[k] != null) return obj[k];
    }
    return '';
  }

  /* ── format parsers ──────────────────────────────── */

  function fromNessusCsv(rows) {
    return rows
      .filter((r) => (pick(r, 'Risk') || '').toLowerCase() !== 'none' || pick(r, 'CVE'))
      .map((r) => {
        const cvss = parseFloat(pick(r, 'CVSS v3.0 Base Score', 'CVSS v2.0 Base Score', 'CVSS'));
        const desc = [pick(r, 'Synopsis'), pick(r, 'Description')].filter(Boolean).join('\n\n');
        return base({
          tool: 'Nessus',
          title: pick(r, 'Name'),
          description: desc,
          solution: pick(r, 'Solution'),
          severity: normSeverity(pick(r, 'Risk'), cvss),
          cvss: isNaN(cvss) ? null : cvss,
          cve: extractCves(pick(r, 'CVE'), pick(r, 'Name')),
          rule: pick(r, 'Plugin ID'),
          asset: pick(r, 'Host'),
          port: pick(r, 'Port') === '0' ? '' : pick(r, 'Port')
        });
      });
  }

  function fromOpenVasCsv(rows) {
    return rows.map((r) => {
      const cvss = parseFloat(pick(r, 'CVSS'));
      return base({
        tool: 'OpenVAS',
        title: pick(r, 'NVT Name'),
        description: [pick(r, 'Summary'), pick(r, 'Specific Result')].filter(Boolean).join('\n\n'),
        solution: pick(r, 'Solution'),
        severity: normSeverity(pick(r, 'Severity'), cvss),
        cvss: isNaN(cvss) ? null : cvss,
        cve: extractCves(pick(r, 'CVEs'), pick(r, 'NVT Name')),
        rule: pick(r, 'NVT OID'),
        asset: pick(r, 'Hostname') || pick(r, 'IP'),
        port: pick(r, 'Port')
      });
    });
  }

  function fromGenericRows(rows, toolName) {
    return rows.map((r) => {
      const cvss = parseFloat(pick(r, 'cvss', 'cvssscore', 'score'));
      const url = pick(r, 'url', 'uri', 'endpoint');
      const title = pick(r, 'title', 'name', 'finding', 'issue', 'vulnerability', 'summary', 'check');
      const desc = pick(r, 'description', 'details', 'detail', 'synopsis', 'message');
      return base({
        tool: pick(r, 'tool', 'source', 'scanner') || toolName || 'Imported',
        title: title || 'Untitled finding',
        description: desc,
        solution: pick(r, 'solution', 'remediation', 'fix', 'recommendation'),
        severity: normSeverity(pick(r, 'severity', 'risk', 'priority', 'level'), isNaN(cvss) ? null : cvss),
        cvss: isNaN(cvss) ? null : cvss,
        cve: extractCves(pick(r, 'cve', 'cves', 'cveid', 'id'), title),
        cwe: extractCwes(pick(r, 'cwe', 'cweid', 'cwes')),
        rule: pick(r, 'rule', 'ruleid', 'pluginid', 'checkid', 'id'),
        asset: pick(r, 'host', 'asset', 'hostname', 'ip', 'target', 'domain') || hostFromUrl(url),
        port: pick(r, 'port') || (url ? portFromUrl(url) : ''),
        url,
        file: pick(r, 'file', 'path', 'location'),
        line: pick(r, 'line', 'startline'),
        pkg: pick(r, 'package', 'pkg', 'pkgname', 'component'),
        installed: pick(r, 'installedversion', 'version', 'installed'),
        fixed: pick(r, 'fixedversion', 'fixed', 'fixedin')
      });
    });
  }

  function fromSarif(doc) {
    const out = [];
    (doc.runs || []).forEach((run) => {
      const driver = (run.tool && run.tool.driver) || {};
      const toolName = driver.name || 'SARIF';
      const rules = {};
      (driver.rules || []).forEach((r) => { rules[r.id] = r; });
      (run.tool && run.tool.extensions || []).forEach((ext) => (ext.rules || []).forEach((r) => { rules[r.id] = r; }));
      const target = (run.originalUriBaseIds && run.originalUriBaseIds.SRCROOT && run.originalUriBaseIds.SRCROOT.uri) || '';

      (run.results || []).forEach((res) => {
        const rule = rules[res.ruleId] || (res.rule && rules[res.rule.id]) || {};
        const props = rule.properties || {};
        const secSev = parseFloat(props['security-severity'] || (res.properties && res.properties['security-severity']));
        const loc = (res.locations && res.locations[0] && res.locations[0].physicalLocation) || {};
        const file = (loc.artifactLocation && loc.artifactLocation.uri) || '';
        const msg = (res.message && (res.message.text || res.message.markdown)) || '';
        const title = (rule.shortDescription && rule.shortDescription.text) || rule.name || res.ruleId || msg.split('\n')[0];
        const tags = (props.tags || []).concat(props.cwe || []);
        const helpText = (rule.help && rule.help.text) || '';
        out.push(base({
          tool: toolName,
          title,
          description: [msg, rule.fullDescription && rule.fullDescription.text].filter(Boolean).join('\n\n'),
          solution: helpText.length < 2000 ? helpText : helpText.slice(0, 2000) + '…',
          severity: !isNaN(secSev) ? fromCvss(secSev) : normSeverity(res.level || (rule.defaultConfiguration && rule.defaultConfiguration.level) || 'warning'),
          cvss: isNaN(secSev) ? null : secSev,
          cve: extractCves(res.ruleId || '', title, msg),
          cwe: extractCwes(tags),
          rule: res.ruleId || '',
          asset: target || toolName + ' scan',
          file,
          line: (loc.region && loc.region.startLine) || ''
        }));
      });
    });
    return out;
  }

  function fromTrivy(doc) {
    const out = [];
    const artifact = doc.ArtifactName || '';
    (doc.Results || []).forEach((r) => {
      const target = r.Target || '';
      (r.Vulnerabilities || []).forEach((v) => {
        const cvss = bestCvss(v.CVSS);
        out.push(base({
          tool: 'Trivy',
          title: v.Title || `${v.VulnerabilityID} in ${v.PkgName}`,
          description: v.Description || '',
          solution: v.FixedVersion ? `Upgrade ${v.PkgName} to ${v.FixedVersion}` : 'No fixed version published yet.',
          severity: normSeverity(v.Severity, cvss),
          cvss,
          cve: extractCves(v.VulnerabilityID || ''),
          cwe: extractCwes(v.CweIDs || []),
          rule: v.VulnerabilityID || '',
          asset: artifact || target,
          file: target,
          pkg: v.PkgName || '',
          installed: v.InstalledVersion || '',
          fixed: v.FixedVersion || ''
        }));
      });
      (r.Misconfigurations || []).forEach((m) => {
        if (m.Status && m.Status !== 'FAIL') return;
        out.push(base({
          tool: 'Trivy',
          title: m.Title || m.ID,
          description: [m.Message, m.Description].filter(Boolean).join('\n\n'),
          solution: m.Resolution || '',
          severity: normSeverity(m.Severity),
          rule: m.ID || m.AVDID || '',
          asset: artifact || target,
          file: target,
          line: (m.CauseMetadata && m.CauseMetadata.StartLine) || ''
        }));
      });
      (r.Secrets || []).forEach((s) => {
        out.push(base({
          tool: 'Trivy',
          title: `Exposed secret: ${s.Title || s.RuleID}`,
          description: `Secret detected (${s.Category || 'credential'}) — ${s.Match ? 'match redacted' : ''}`.trim(),
          solution: 'Rotate the secret and remove it from source.',
          severity: normSeverity(s.Severity),
          cwe: [798],
          rule: s.RuleID || '',
          asset: artifact || target,
          file: target,
          line: s.StartLine || ''
        }));
      });
    });
    return out;
  }

  function bestCvss(cvssMap) {
    if (!cvssMap) return null;
    let best = null;
    Object.values(cvssMap).forEach((c) => {
      const s = c.V3Score != null ? c.V3Score : c.V2Score;
      if (s != null && (best == null || s > best)) best = s;
    });
    return best;
  }

  function fromZap(doc) {
    const out = [];
    const sites = Array.isArray(doc.site) ? doc.site : [doc.site];
    const riskMap = { 0: 'info', 1: 'low', 2: 'medium', 3: 'high' };
    sites.filter(Boolean).forEach((site) => {
      const siteName = site['@name'] || '';
      (site.alerts || []).forEach((a) => {
        const instances = a.instances && a.instances.length ? a.instances : [{ uri: siteName }];
        const uri = instances[0].uri || siteName;
        const extra = instances.length > 1 ? `\n\nAffects ${instances.length} URLs, e.g.:\n` + instances.slice(0, 5).map((x) => '• ' + x.uri).join('\n') : '';
        out.push(base({
          tool: 'OWASP ZAP',
          title: a.alert || a.name,
          description: stripHtml(a.desc) + extra,
          solution: stripHtml(a.solution),
          severity: riskMap[a.riskcode] || normSeverity(a.riskdesc && a.riskdesc.split(' ')[0]),
          cwe: extractCwes(a.cweid),
          rule: String(a.pluginid || ''),
          asset: site['@host'] || hostFromUrl(siteName),
          port: site['@port'] || portFromUrl(siteName),
          url: uri
        }));
      });
    });
    return out;
  }

  /* ── detection ───────────────────────────────────── */

  function detectAndParse(text, filename) {
    const name = (filename || '').toLowerCase();
    const trimmed = text.trim();
    if (!trimmed) throw new Error('The file is empty.');

    if (trimmed[0] === '{' || trimmed[0] === '[') {
      let doc;
      try { doc = JSON.parse(trimmed); } catch (e) { throw new Error('Looks like JSON but could not be parsed: ' + e.message); }
      if (doc && Array.isArray(doc.runs) && (doc.version || doc.$schema)) return { format: 'SARIF', findings: fromSarif(doc) };
      if (doc && Array.isArray(doc.Results) && ('SchemaVersion' in doc || 'ArtifactName' in doc)) return { format: 'Trivy JSON', findings: fromTrivy(doc) };
      if (doc && doc.site && ('@programName' in doc || '@version' in doc || Array.isArray(doc.site) || doc.site.alerts)) return { format: 'OWASP ZAP JSON', findings: fromZap(doc) };
      const arr = Array.isArray(doc) ? doc : (doc.findings || doc.vulnerabilities || doc.results || doc.issues);
      if (Array.isArray(arr)) return { format: 'Generic JSON', findings: fromGenericRows(arr.map(flatten), doc.tool || doc.scanner) };
      throw new Error('Unrecognised JSON. Expected SARIF, Trivy, ZAP, or an array of findings.');
    }

    const rows = parseCsv(text);
    if (!rows.length) throw new Error('No rows found. Expected a CSV with a header row.');
    const headers = Object.keys(rows[0]).map((h) => h.toLowerCase());
    if (headers.includes('plugin id') && headers.includes('risk')) return { format: 'Nessus CSV', findings: fromNessusCsv(rows) };
    if (headers.includes('nvt name') || headers.includes('nvt oid')) return { format: 'OpenVAS CSV', findings: fromOpenVasCsv(rows) };
    if (name.endsWith('.csv') || headers.length > 1) return { format: 'Generic CSV', findings: fromGenericRows(rows) };
    throw new Error('Unrecognised format.');
  }

  /** Flatten one level so generic JSON like {location:{host:…}} still maps. */
  function flatten(o) {
    if (!o || typeof o !== 'object') return {};
    const out = {};
    Object.entries(o).forEach(([k, v]) => {
      if (v && typeof v === 'object' && !Array.isArray(v)) Object.entries(v).forEach(([k2, v2]) => { if (!(k2 in out)) out[k2] = scalar(v2); });
      else out[k] = scalar(v);
    });
    return out;
  }

  function scalar(v) { return Array.isArray(v) ? v.join(', ') : (v == null ? '' : String(v)); }

  global.ImproveParsers = { detectAndParse, parseCsv, SEVERITIES };
})(window);
