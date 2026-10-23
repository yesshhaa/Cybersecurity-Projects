// Run with: node --test
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const A = require('../analyzer');

const sample = (name) => fs.readFileSync(path.join(__dirname, '..', 'samples', name), 'utf8');
const titles = (r) => r.findings.map((f) => f.title);
const byName = (report, name) => report.results.find((r) => r.cookie.name === name);

test('parses raw response headers and ignores non-cookie headers', () => {
  const cookies = A.parseInput('HTTP/1.1 200 OK\nContent-Type: text/html\nSet-Cookie: a=1; Path=/; Secure; HttpOnly; SameSite=strict');
  assert.strictEqual(cookies.length, 1);
  assert.deepStrictEqual(
    { name: cookies[0].name, secure: cookies[0].attrs.secure, httponly: cookies[0].attrs.httponly, samesite: cookies[0].attrs.samesite },
    { name: 'a', secure: true, httponly: true, samesite: 'Strict' });
});

test('treats bare name=value pairs as document.cookie output', () => {
  const cookies = A.parseInput('sessionid=abc; theme=dark');
  assert.deepStrictEqual(cookies.map((c) => [c.name, c.source]), [['sessionid', 'js'], ['theme', 'js']]);
});

test('vulnerable sample grades F with the expected findings', () => {
  const report = A.analyze(sample('vulnerable.txt'));
  assert.strictEqual(report.grade.letter, 'F');
  assert.ok(titles(byName(report, 'PHPSESSID')).includes('Sequential / guessable numeric session ID'));
  assert.ok(titles(byName(report, 'remember_token')).includes('Session ID is a Unix timestamp'));
  assert.ok(titles(byName(report, 'user_role')).includes('Tamperable client-side authorization data'));
  assert.ok(titles(byName(report, 'ab_test')).includes('SameSite=None without Secure'));
});

test('hardened sample grades A', () => {
  const report = A.analyze(sample('hardened.txt'));
  assert.strictEqual(report.grade.letter, 'A');
  assert.strictEqual(report.grade.counts.high + report.grade.counts.critical + report.grade.counts.medium, 0);
});

test('flags alg:none and missing exp in JWTs', () => {
  const report = A.analyze(sample('jwt.txt'));
  const t = titles(byName(report, 'access_token'));
  assert.ok(t.includes('Unsigned JWT (alg: none)'));
  assert.ok(t.includes('JWT has no expiry (exp)'));
  assert.ok(titles(byName(report, 'auth')).includes('PII (email) exposed in JWT payload'));
});

test('reads browser-extension JSON exports', () => {
  const report = A.analyze(sample('export.json'));
  assert.strictEqual(report.results.length, 3);
  assert.ok(titles(byName(report, 'connect.sid')).includes('Session cookie shared with every subdomain'));
});

test('__Host- prefix violations are reported', () => {
  const r = A.analyze('Set-Cookie: __Host-sid=q8Rk3vZ1yT6pN0wLs2HbX9cFjEa4Gm7Ud5KiOrPeYQ0; Path=/app; Secure; HttpOnly; SameSite=Lax').results[0];
  assert.ok(titles(r).includes('__Host- prefix requirements violated'));
});

test('entropy estimate separates random tokens from weak ones', () => {
  assert.ok(A.entropy('q8Rk3vZ1yT6pN0wLs2HbX9cFjEa4Gm7Ud5KiOrPeYQ0').bits >= 128);
  assert.ok(A.entropy('abababababababababababab').bits < 64);
  assert.ok(A.entropy('12345').bits < 20);
});

test('hardened header for a weak session cookie is secure and uses a fresh token', () => {
  const r = A.analyze('Set-Cookie: PHPSESSID=1048576; Path=/').results[0];
  assert.match(r.hardened.header, /^Set-Cookie: __Host-PHPSESSID=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Lax$/);
  // the regenerated header must itself pass the audit
  const again = A.analyze(r.hardened.header).results[0];
  assert.strictEqual(again.score, 100);
});
