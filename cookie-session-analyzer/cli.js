#!/usr/bin/env node
/**
 * cli.js — Cookie & Session Analyzer (command line)
 * Audits the cookies a live site sets, or Set-Cookie headers from a file / stdin.
 *
 *   node cli.js https://example.com
 *   node cli.js samples/vulnerable.txt --md report.md
 *   curl -sI https://example.com | node cli.js -
 */

'use strict';

const fs = require('fs');
const A = require('./analyzer');

const SEVERITY = ['critical', 'high', 'medium', 'low', 'info'];
const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code) => (s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const C = {
  critical: paint('1;31'), high: paint('31'), medium: paint('33'), low: paint('32'), info: paint('2'),
  bold: paint('1'), dim: paint('2'), green: paint('32'),
};

function usage(code) {
  console.log(`Cookie & Session Analyzer

Usage: node cli.js <target> [options]

  <target>               URL (http/https), path to a file of headers / JSON export, or - for stdin

Options:
  --json <file>          Write a JSON report
  --md <file>            Write a Markdown report
  --fail-on <severity>   Exit 1 if any finding is at or above this severity (critical|high|medium|low)
  --max-redirects <n>    Redirect hops to follow for URLs, collecting cookies on each (default 5)
  -q, --quiet            Only print the grade line
  -h, --help             Show this help`);
  process.exit(code);
}

function parseArgs(argv) {
  const opts = { target: null, json: null, md: null, failOn: null, maxRedirects: 5, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') usage(0);
    else if (a === '--json') opts.json = argv[++i];
    else if (a === '--md') opts.md = argv[++i];
    else if (a === '--fail-on') opts.failOn = argv[++i];
    else if (a === '--max-redirects') opts.maxRedirects = parseInt(argv[++i], 10);
    else if (a === '-q' || a === '--quiet') opts.quiet = true;
    else if (!opts.target) opts.target = a;
    else usage(2);
  }
  if (!opts.target) usage(2);
  if (opts.failOn && !SEVERITY.slice(0, 4).includes(opts.failOn)) {
    console.error('--fail-on must be one of critical, high, medium, low');
    process.exit(2);
  }
  return opts;
}

// Follows redirects by hand so cookies set on intermediate hops (login redirects, geo redirects…) are audited too
async function fetchSetCookies(url, maxRedirects) {
  const lines = [];
  let current = url;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const res = await fetch(current, {
      redirect: 'manual',
      headers: { 'User-Agent': 'cookie-session-analyzer/1.0 (+https://github.com/yesshhaa/Cybersecurity-Projects)' },
      signal: AbortSignal.timeout(10000),
    });
    const cookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    console.error(C.dim(`[*] ${res.status} ${current} — ${cookies.length} Set-Cookie header${cookies.length === 1 ? '' : 's'}`));
    cookies.forEach((c) => lines.push('Set-Cookie: ' + c));
    const loc = res.headers.get('location');
    if (res.status < 300 || res.status >= 400 || !loc) break;
    current = new URL(loc, current).href;
  }
  return lines.join('\n');
}

async function readInput(target, maxRedirects) {
  if (/^https?:\/\//i.test(target)) return fetchSetCookies(target, maxRedirects);
  if (target === '-') return fs.readFileSync(0, 'utf8');
  return fs.readFileSync(target, 'utf8');
}

function printReport(report) {
  const g = report.grade;
  const gradeColor = { A: C.green, B: C.green, C: C.medium, D: C.high, F: C.critical }[g.letter];
  console.log('');
  report.results.forEach((r) => {
    console.log(C.bold(`■ ${r.cookie.name || '(unnamed)'}`) + C.dim(`  ${r.kind} · ${r.score}/100`));
    if (!r.findings.length) console.log('  ' + C.green('✓ no issues'));
    r.findings.forEach((f) => {
      console.log(`  ${C[f.severity](('[' + f.severity.toUpperCase() + ']').padEnd(10))} ${f.title}`);
      if (f.fix) console.log(C.dim(`             → ${f.fix}`));
    });
    console.log('');
  });
  console.log(C.bold('Hardened headers'));
  report.results.forEach((r) => {
    r.hardened.notes.forEach((n) => console.log(C.dim(`  # ${r.cookie.name}: ${n}`)));
    console.log('  ' + r.hardened.header);
  });
  console.log('');
  printGrade(report, gradeColor);
}

function printGrade(report, gradeColor) {
  const g = report.grade;
  const counts = SEVERITY.filter((s) => g.counts[s]).map((s) => C[s](`${g.counts[s]} ${s}`)).join(', ') || 'no findings';
  const color = gradeColor || ((s) => s);
  console.log(`${C.bold('Grade:')} ${color(C.bold(g.letter))} (${g.score}/100) — ${report.results.length} cookie(s) — ${counts}`);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  let text;
  try {
    text = await readInput(opts.target, opts.maxRedirects);
  } catch (e) {
    console.error(`[!] Could not read ${opts.target}: ${e.cause ? e.cause.message || e.cause.code : e.message}`);
    process.exit(2);
  }

  const report = A.analyze(text);
  if (!report.results.length) {
    console.log('[*] No cookies found — nothing to audit.');
    return;
  }

  if (opts.quiet) printGrade(report);
  else printReport(report);

  if (opts.json) {
    fs.writeFileSync(opts.json, JSON.stringify(A.toJSONReport(report), null, 2));
    console.error(`[*] JSON report saved to ${opts.json}`);
  }
  if (opts.md) {
    fs.writeFileSync(opts.md, A.toMarkdownReport(report));
    console.error(`[*] Markdown report saved to ${opts.md}`);
  }

  if (opts.failOn) {
    const threshold = SEVERITY.indexOf(opts.failOn);
    const hit = report.results.some((r) => r.findings.some((f) => SEVERITY.indexOf(f.severity) <= threshold));
    if (hit) process.exitCode = 1;
  }
}

main();
