// Run with: node --test   (from the improve-2.0 folder)
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Load the browser scripts into a shared sandbox that stands in for `window`.
const ctx = vm.createContext({});
ctx.window = ctx;
for (const f of ['playbooks.js', 'parsers.js', 'engine.js']) {
  vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'js', f), 'utf8'), ctx, { filename: f });
}
const { detectAndParse } = ctx.ImproveParsers;
const E = ctx.ImproveEngine;
const KEV = new Set(ctx.ImprovePlaybooks.KEV_SEED);
const sample = (n) => fs.readFileSync(path.join(__dirname, '..', 'samples', n), 'utf8');
const planFor = (findings) => E.buildPlan(findings, { kev: KEV, assetInfo: (f) => ({ exposure: E.inferExposure(f.asset, f), critical: false }) });

test('detects each sample format', () => {
  assert.strictEqual(detectAndParse(sample('nessus-office-network.csv'), 'a.csv').format, 'Nessus CSV');
  assert.strictEqual(detectAndParse(sample('zap-storefront.json'), 'a.json').format, 'OWASP ZAP JSON');
  assert.strictEqual(detectAndParse(sample('trivy-storefront-image.json'), 'a.json').format, 'Trivy JSON');
});

test('Nessus: drops Risk=None rows and keeps CVEs', () => {
  const { findings } = detectAndParse(sample('nessus-office-network.csv'), 'n.csv');
  assert.strictEqual(findings.length, 12);
  assert.ok(findings.some((f) => f.cve.includes('CVE-2017-0144')));
});

test('SARIF results map severity, CWE and location', () => {
  const sarif = JSON.stringify({
    version: '2.1.0', runs: [{
      tool: { driver: { name: 'Semgrep', rules: [{ id: 'py.sqli', shortDescription: { text: 'SQL built from user input' }, properties: { tags: ['CWE-89: SQL Injection'], 'security-severity': '8.1' } }] } },
      results: [{ ruleId: 'py.sqli', level: 'error', message: { text: 'f-string in execute()' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'app/db.py' }, region: { startLine: 42 } } }] }]
    }]
  });
  const [f] = detectAndParse(sarif, 'x.sarif').findings;
  assert.strictEqual(f.severity, 'high');
  assert.deepStrictEqual([...f.cwe], [89]);
  assert.strictEqual(f.file, 'app/db.py');
  assert.strictEqual(E.matchPlaybook(f).id, 'sqli');
});

test('generic CSV with quoted commas and newlines', () => {
  const csv = 'title,severity,host,description\n"MFA not enforced",high,m365.example.com,"line one,\nline two"\n';
  const [f] = detectAndParse(csv, 'g.csv').findings;
  assert.strictEqual(f.title, 'MFA not enforced');
  assert.strictEqual(f.description, 'line one,\nline two');
  assert.strictEqual(E.matchPlaybook(f).id, 'mfa-missing');
});

test('playbook matching: CVE, rule id, package and keyword paths', () => {
  const zap = detectAndParse(sample('zap-storefront.json'), 'z.json').findings;
  const trivy = detectAndParse(sample('trivy-storefront-image.json'), 't.json').findings;
  const nessus = detectAndParse(sample('nessus-office-network.csv'), 'n.csv').findings;
  const id = (list, pred) => E.matchPlaybook(list.find(pred)).id;
  assert.strictEqual(id(zap, (f) => f.rule === '10035'), 'hsts'); // rule beats CWE-319
  assert.strictEqual(id(trivy, (f) => f.pkg === 'lodash'), 'vulnerable-package'); // package beats CWE-94
  assert.strictEqual(id(trivy, (f) => f.cve.includes('CVE-2021-44228')), 'log4shell');
  assert.strictEqual(id(trivy, (f) => /secret/i.test(f.title)), 'hardcoded-secret');
  assert.strictEqual(id(nessus, (f) => /TLS Version 1\.0/.test(f.title)), 'tls-weak');
  assert.strictEqual(id(nessus, (f) => /Telnet/.test(f.title)), 'cleartext-service');
});

test('every playbook ends in at least one verification check', () => {
  for (const p of ctx.ImprovePlaybooks.PLAYBOOKS.concat(ctx.ImprovePlaybooks.GENERIC)) {
    assert.ok(p.verify.length > 0, p.id);
    for (const v of p.verify) assert.ok(v.check && v.cmd && v.expect, p.id);
  }
});

test('KEV + internet exposure puts exploited issues in "Fix today"', () => {
  const findings = ['nessus-office-network.csv', 'zap-storefront.json', 'trivy-storefront-image.json']
    .flatMap((n) => detectAndParse(sample(n), n).findings);
  const plan = planFor(findings);
  const now = plan.filter((g) => g.bucket === 'now').map((g) => g.pb.id);
  for (const want of ['rdp-exposed', 'smbv1', 'log4shell', 'sqli', 'hardcoded-secret']) assert.ok(now.includes(want), want);
  assert.ok(plan.find((g) => g.pb.id === 'version-disclosure').bucket !== 'now');
  for (let i = 1; i < plan.length; i++) assert.ok(plan[i - 1].score >= plan[i].score, 'sorted by score');
});

test('exposure inference', () => {
  assert.strictEqual(E.inferExposure('192.168.1.5', {}), 'internal');
  assert.strictEqual(E.inferExposure('fileserver', {}), 'internal');
  assert.strictEqual(E.inferExposure('shop.example.com', {}), 'internet');
  assert.strictEqual(E.inferExposure('acme/app:1.0', {}), 'code');
});

test('verify commands are filled with the finding\'s host and port', () => {
  const [f] = detectAndParse('title,severity,host,port\nTLS Version 1.0 Protocol Detection,medium,shop.example.com,8443\n', 'x.csv').findings;
  const pb = E.matchPlaybook(f);
  const cmd = E.fill(pb.verify[0].cmd, E.tokensFor(f, pb));
  assert.strictEqual(cmd, 'openssl s_client -connect shop.example.com:8443 -tls1 </dev/null');
});
