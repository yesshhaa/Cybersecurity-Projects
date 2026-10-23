# Hypothesis: unusual PowerShell execution

> An attacker who gets code running on a Windows endpoint will often hand off to PowerShell in a way
> that hides what it is doing: an **encoded command in a hidden window**, a **download-and-execute
> one-liner**, or a PowerShell child of an **Office document or script host**. Legitimate
> administration rarely combines these, so looking for the *combinations* (and not any single flag)
> should give a high-signal alert.

| | |
|---|---|
| Rule | [`rule.yml`](rule.yml) (Sigma, `process_creation` / `windows`) |
| Test events | [`generate_events.py`](generate_events.py) → `events.jsonl` (22 synthetic Sysmon EID 1 events) |
| Latest results | [`results.md`](results.md) |
| ATT&CK | T1059.001 PowerShell · T1027.010 Command Obfuscation · T1564.003 Hidden Window · T1105 Ingress Tool Transfer |
| Status | experimental. Passes the lab tests but has not been tuned against real telemetry yet |

## 1. The behavior

PowerShell ships with Windows and can do almost anything an attacker needs: discovery, download,
and in-memory execution. Three things it allows on the command line are especially useful to
attackers and much less useful to administrators:

- **`-EncodedCommand`**: takes a Base64 string of UTF-16LE text. Microsoft documents it for
  commands with awkward quoting. Attackers use it to keep the script out of plain-text logs and away
  from simple string matching. Any unambiguous prefix works (`-e`, `-ec`, `-en`, `-enc`, ...), and
  Windows PowerShell also accepts `/` as the switch character.
- **`-WindowStyle Hidden`** (or `-w 1`): no console window flashes up for the user. ATT&CK uses
  `powershell.exe -WindowStyle Hidden` as its example for T1564.003.
- **Download cradles**: `(New-Object Net.WebClient).DownloadString(...)`, `Invoke-WebRequest`,
  `irm`, and others, piped into `IEX` / `Invoke-Expression`, so the second stage runs from memory
  and never touches disk.

Each of these alone shows up in normal admin work: scheduled tasks run hidden, and management
tools use encoded commands. Combinations are the stronger signal, and so is the process
**lineage**: Word, Excel, Outlook, `mshta`, `wscript`/`cscript`, or a web/SQL server worker
starting PowerShell is the usual shape of phishing-document and web-shell intrusions.

What the rule therefore looks for (PowerShell image, or a renamed copy caught via `OriginalFileName`):

| Pattern | Logic | Why |
|---|---|---|
| **A** | encoded command **and** hidden window | hiding both *what* runs and *that* it runs |
| **B** | download primitive **and** `IEX`/`Invoke-Expression` | fetch-and-run in memory |
| **C** | suspicious parent **and** any one of the four building blocks | the parent supplies the missing context |

## 2. Public documentation used

| Source | What it contributed |
|---|---|
| [MITRE ATT&CK T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Technique scope, download-and-execute-in-memory behavior |
| [MITRE ATT&CK T1564.003: Hidden Window](https://attack.mitre.org/techniques/T1564/003/) | `powershell.exe -WindowStyle Hidden` as the canonical example |
| [MITRE ATT&CK T1027.010: Command Obfuscation](https://attack.mitre.org/techniques/T1027/010/) · [T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) | Tagging for encoding and download |
| [Microsoft: about_PowerShell_exe (5.1)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1) | `-EncodedCommand` must be Base64 of UTF-16LE, `-WindowStyle` values |
| [Microsoft: about_Pwsh (7.x)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh) | pwsh aliases: `-e`/`-ec` (EncodedCommand), `-w` (WindowStyle), and `-ex`/`-ep` (ExecutionPolicy), which the regex must *not* match |
| [Red Canary Threat Detection Report: PowerShell](https://redcanary.com/threat-detection-report/techniques/powershell/) | Detection ideas from the field: encoded-command variants, hidden flags, `IEX` + `DownloadString`, and a warning that admins use encoding too |
| [SigmaHQ `proc_creation_win_powershell_encode`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_encode.yml) ([mirror](https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_powershell_encode/)) | Prior art. It uses substring matches (`-e`, `-en`, `-enc`, `-enco`, `-ec`) plus a `-Encoding` exclusion, and the Azure Guest Configuration filter reused here |
| [Sigma specification](https://github.com/SigmaHQ/sigma-specification) | Modifier semantics (`windash`, `re|i`, `all`), condition grammar |

## 3. Design decisions

- **Regex instead of `contains` for the encoded flag.** The prior-art substring `-enco` also matches
  `-Encoding`, so that rule needs a `-Encoding` exclusion, and an attacker can then append
  `-Encoding` to the command line to get past it. The regex `\s[-/–—―]e(c|n(c(o(d…)?)?)?)?\s` only
  accepts real prefixes of `EncodedCommand` followed by whitespace. That leaves `-Encoding`,
  `-ep`, and `-ex` alone without needing an exclusion. Mutation test
  `test_mutation_naive_encoded_contains` shows the substring version failing case `ps-13`.
- **Dash variants.** The `[-/–—―]` class is the regex version of Sigma's `windash` modifier, so it
  also covers en/em dashes pasted from documents (`ps-04`).
- **Renamed binaries.** `OriginalFileName` (from the PE header, recorded by Sysmon) catches
  `powershell.exe` copied to another name (`ps-06`).
- **Encoded-only is deliberately out of scope.** A bare `-EncodedCommand` from a normal parent is too
  common in management tooling to page on. It is recorded as a known false negative (`ps-20`) and
  should be a lower-severity hunting rule.

## 4. Testing

`python lab.py test powershell-unusual-execution --report` evaluates the rule against every event
and fails if any outcome differs from the case's declared expectation.

| Category | Count | Meaning |
|---|---|---|
| true_positive | 10 | malicious shapes that must alert: maldoc, slash/en-dash/upper-case variants, renamed binary, WebClient and `irm\|iex` cradles, mshta and Excel lineage |
| true_negative | 8 | benign or near-miss events that must not alert: admin queries, hidden scheduled task, `-Encoding`, `-ep`, download-to-disk, Word plus a harmless script, cmd.exe child, Azure filter |
| known_false_positive | 1 | alerts, and we accept it (Chocolatey installer) |
| known_false_negative | 3 | misses, and we accept it (encoded only, string-concatenated cradle, payload in an env var) |

Result: **22/22 behave as expected.** On top of that, `tests/test_sigma_lite.py` mutates the rule
(drops the filter, drops `OriginalFileName`, swaps in the naive substring, lets the parent alone
fire) and checks that **exactly** the case guarding that logic fails. That shows the case suite is
able to catch a regression, not just pass.

## 5. Limitations

- **Command line only.** The rule sees the process command line, so anything assembled inside
  PowerShell is invisible to it: string concatenation (`ps-21`), environment variables (`ps-22`),
  `-Command -` reading from stdin, scripts on disk via `-File`. Pair it with **Script Block
  Logging (Event ID 4104)** and AMSI-based detections, which see the de-obfuscated script.
- **Token-level evasion.** `cmd.exe` strips caret insertion (`-e^nc`) before the process starts,
  so carets don't reach the logged command line. Quote insertion does reach it: `"-e"nc` or `-"w"
  hidden` is parsed by PowerShell as the normal switch but defeats the regex, which expects the switch
  to be preceded by whitespace. Other argument styles the regex doesn't model (a `:` separator,
  non-breaking spaces) are untested too. A good next case for the lab.
- **Other hosts.** PowerShell code run without `powershell.exe`/`pwsh.exe` (e.g. via
  `System.Management.Automation.dll` loaded in a custom binary, or PowerShell ISE) is out of scope.
- **Telemetry prerequisites.** Needs Sysmon Event ID 1, or Security Event ID 4688 with
  "Include command line in process creation events" enabled. 4688 has no `OriginalFileName`, so the
  renamed-binary case is lost there.
- **Regex portability.** The dash class is written with `–`-style escapes, which Python and
  .NET accept. Some backends (e.g. PCRE in Splunk) want `\x{2013}`. Check the converted query.
- **Synthetic data.** All 22 events are hand-built to mirror real shapes. They show the logic works,
  not how noisy the rule is. Run it over 2–4 weeks of real process telemetry before promoting
  it past `experimental`.

## 6. Expected false positives and tuning

| Source | Why it fires | Suggested tuning |
|---|---|---|
| Software bootstrap one-liners (Chocolatey, Scoop, vendor agents) | genuine `iex ... DownloadString(...)` (`ps-19`) | allow-list by `ParentImage` + the exact trusted URL, **not** by URL substring alone |
| SCCM / Intune / RMM agents | hidden + encoded is how many of them push scripts | filter on the signed agent's `ParentImage` path, e.g. `CcmExec.exe` |
| Office add-ins that shell out | lineage rule (pattern C) | filter on the specific add-in script path, and keep pattern A/B unfiltered |
| `irm ` / `iwr ` substrings | short aliases can appear inside other words (`confirm `) | pattern B also requires `IEX`, which keeps this rare. Watch for it during tuning |
| Azure Guest Configuration | hidden encoded commands from `gc_worker.exe` | already filtered (`ps-18`) |

When tuning, add every new exclusion as a `filter_optional_*` block **and** a matching
`true_negative` event, so the lab keeps proving the exclusion stays narrow.
