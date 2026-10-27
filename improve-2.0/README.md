# Improve 2.0 — Security Fix Navigator

A browser tool for small businesses and IT generalists. Import the findings your security tools already produce, and Improve 2.0 explains what each issue means, how it could be exploited, what to fix first, and how to **prove** the fix worked. Every finding ends in a practical, verifiable action — not just a severity score.

It runs entirely client-side: reports are parsed in the browser and progress is saved to `localStorage`. Nothing is uploaded.

**References:** CISA Known Exploited Vulnerabilities catalog · OWASP Top 10 · CWE · CIS hardening guidance

---

## Why this project

Scanners are good at finding problems and bad at helping the person who has to fix them. A small-business IT generalist running Nessus, ZAP or Trivy gets hundreds of rows sorted by CVSS and three questions nobody answers:

- **What does this actually mean for me?** "SSL Certificate Cannot Be Trusted" and "MS17-010" are not plain language.
- **What do I fix first?** CVSS says a medium RDP finding and a medium missing header are equal. An attacker doesn't.
- **How do I know it's fixed?** Most tools stop at "apply the patch". Closing a ticket isn't proof.

Improve 2.0 answers all three, and the last one is the point: each finding comes with a copy-paste check and the exact output that means "fixed".

## How it works

| Step | What happens |
|---|---|
| **Import** | Drop exports from Nessus (CSV), OpenVAS/Greenbone (CSV), OWASP ZAP (JSON), Trivy (JSON — vulns, misconfigs, secrets), any SARIF tool (Semgrep, CodeQL, Snyk, Checkov…), or a generic CSV/JSON. Formats are auto-detected and duplicates merge. |
| **Explain** | Findings are matched to one of 29 remediation playbooks by CVE → tool rule ID → package → CWE → keywords. Each playbook gives *what it means*, *how it could be exploited*, *impact*, and fix steps per platform (Nginx / Apache / IIS / Windows / Linux / cloud). |
| **Prioritise** | A transparent 0–100 score — every point is shown with its reason — sorts work into **Fix today / This week / This month / Backlog**. Findings one fix resolves (e.g. one package upgrade across five images) become a single action. |
| **Verify** | Each affected host gets checks with its real host/port/package filled in, e.g. `openssl s_client -connect shop.example.com:443 -tls1` → *pass when: handshake failure*. "Verified" stays locked until every check is ticked; evidence notes are kept per finding. Accepting a risk requires a written reason. |
| **Re-scan** | Import the next scan from the same tool: findings you marked fixed that disappeared are auto-verified; anything still reported is reopened. |
| **Report** | Markdown action plan, CSV tracker export, print view, and JSON backup/restore. |

### Priority score

| Factor | Points |
|---|---|
| Severity (critical / high / medium / low / info) | 40 / 30 / 18 / 8 / 2 |
| Exploitability from the playbook (unusual → commonly abused → trivial / mass-scanned) | 7 / 14 / 21 |
| CVE is on CISA's Known Exploited Vulnerabilities list | +20 |
| Exposure (internet-facing / internal / code or image) | 15 / 6 / 4 |
| Internet-facing **and** trivially exploitable — or critical **and** trivially exploitable | +10 |
| Asset marked business-critical by the user | +10 |
| Quick win (fix takes minutes / hours) | +4 / +2 |

Exposure is inferred (RFC 1918 addresses and `.local`/`.corp` names are internal; image refs and file paths are code) and can be overridden per asset in **Tune the ranking**. The KEV list ships with a built-in seed of 30 high-profile CVEs and can be refreshed in-app from [cisagov/kev-data](https://github.com/cisagov/kev-data).

### Playbook coverage

Log4Shell · SMBv1 / EternalBlue · exposed RDP / BlueKeep · weak SSH · end-of-life software · missing OS patches · cleartext protocols (Telnet/FTP) · SNMP default community · default credentials · MFA not enforced · SPF/DKIM/DMARC · weak TLS & ciphers · untrusted/expired certificates · HSTS · CSP · clickjacking · cookie flags · version disclosure · directory listing · permissive CORS · SQL injection · XSS · CSRF · path traversal · open redirect · hard-coded secrets · public cloud storage · containers running as root · vulnerable packages — plus a generic fallback that still ends in a re-scan check.

## Project structure

```
improve-2.0/
├── index.html            # single-page app
├── css/improve.css       # styles (dark + light themes, responsive)
├── js/playbooks.js       # remediation knowledge base: means / exploit / fix / verify
├── js/parsers.js         # format detection + normalisation (SARIF, Trivy, ZAP, Nessus, OpenVAS, CSV/JSON)
├── js/engine.js          # playbook matching, priority scoring, fix-action grouping, command templating
├── js/app.js             # UI, state, re-scan comparison, reports
├── samples/              # demo exports: office network (Nessus), online shop (ZAP), container (Trivy)
└── test/engine.test.js   # parser + engine tests (node --test)
```

## Running it

```bash
cd improve-2.0
python3 -m http.server 8080      # then open http://localhost:8080
```

Opening `index.html` directly works too, except the one-click sample buttons (browsers block `fetch` on `file://`) — drag the files from `samples/` instead.

Tests (Node 18+, no dependencies):

```bash
node --test
```

## Exporting from your tools

| Tool | How |
|---|---|
| Nessus / Tenable | Scan → Report → CSV |
| OpenVAS / Greenbone | Reports → download "CSV Results" |
| OWASP ZAP | `docker run --rm -v "$PWD":/zap/wrk -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://your-site -J zap.json` |
| Trivy | `trivy image --scanners vuln,secret,misconfig --format json -o trivy.json image:tag` |
| Semgrep | `semgrep scan --config auto --sarif -o semgrep.sarif` |
| CodeQL | download the SARIF from the code-scanning workflow |
| Anything else | CSV with columns like `title, severity, host, port, cve, cwe, description, solution` |

## Security notes

- All imported text is HTML-escaped before rendering; ZAP's HTML descriptions are stripped with an inert `DOMParser` document.
- CSV exports prefix cells starting with `= + - @` to block spreadsheet formula injection.
- Trivy secret matches are never displayed — only the rule, file and line.

## What I learned

- How differently each scanner models the same idea (Nessus "Risk", ZAP `riskcode`, SARIF `level` vs `security-severity`) and how to normalise them without losing meaning.
- Why severity alone is a poor queue: real-world exploitation (KEV) and exposure change the order far more than CVSS decimals.
- Writing verification steps forced precision — for every fix, deciding what observable output actually proves it.
