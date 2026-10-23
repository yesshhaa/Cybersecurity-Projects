# Detection Rule Research Lab

A dependency-free Python workbench for turning a **detection hypothesis** ("attackers run PowerShell
in unusual ways") into a **tested Sigma rule**. For each hypothesis it covers the behavior, the
public sources it relies on, the rule, synthetic test events, automated match/non-match tests,
and a written record of limitations and false positives.

**MITRE ATT&CK (first hypothesis):** T1059.001 PowerShell · T1027.010 Command Obfuscation · T1564.003 Hidden Window · T1105 Ingress Tool Transfer

---

## Why this project

Writing a detection rule is easy. Knowing whether it works is harder. A rule that has never seen a
malicious event might not fire. One that has never seen benign admin activity might page the SOC
all night. And a rule that looks fine today can break quietly after someone "tunes" it.

This lab treats detections like code. Every rule ships with test events that say what *should*
happen, a runner that fails when reality disagrees, and documentation honest enough to list the
attacks the rule **misses**.

## How it works

Every hypothesis goes through the same six steps, in its own folder under `hypotheses/`:

1. **Explain the behavior.** What the attacker does, and why it should look different from
   legitimate activity (`HYPOTHESIS.md` §1)
2. **Find public documentation.** MITRE ATT&CK, Microsoft docs, threat reports, existing SigmaHQ
   rules, each listed with what it contributed (§2)
3. **Draft a Sigma rule** (`rule.yml`)
4. **Generate synthetic events** (`generate_events.py` → `events.jsonl`). Each event carries a
   `_lab` label: expected outcome (`match` / `no_match`), category, and a one-line reason
5. **Test.** `lab.py test` evaluates the rule against every event with `sigma_lite.py` and exits
   non-zero on any surprise. Cases fall into four categories:
   - `true_positive`: malicious, must alert
   - `true_negative`: benign or near-miss, must stay quiet
   - `known_false_positive`: benign but alerts. Accepted and documented
   - `known_false_negative`: malicious but missed. Accepted and documented
6. **Document limitations and false positives** with tuning advice (§5–6)

Known FPs and FNs are kept as test cases on purpose. If a later change "fixes" one by accident,
the test run shows it.

### First hypothesis: unusual PowerShell execution

The rule fires on PowerShell (including renamed copies, caught via `OriginalFileName`) when it
sees one of three **combinations**:

| Pattern | Logic | Why |
|---|---|---|
| **A** | encoded command **and** hidden window | hides both *what* runs and *that* it runs |
| **B** | download primitive **and** `IEX` / `Invoke-Expression` | fetch-and-run in memory |
| **C** | Office / script host / `mshta` / web-server parent **and** any of the above building blocks | the parent supplies the missing context |

Full write-up: [`hypotheses/powershell-unusual-execution/HYPOTHESIS.md`](hypotheses/powershell-unusual-execution/HYPOTHESIS.md)

## Project structure

```
detection-rule-lab/
├── lab.py                  # CLI: new / generate / test
├── sigma_lite.py           # Sigma evaluator (subset), errors on anything unsupported
├── yaml_lite.py            # YAML loader fallback (uses PyYAML if installed)
├── templates/              # scaffold copied by `lab.py new`
├── tests/
│   └── test_sigma_lite.py  # evaluator unit tests + rule mutation tests
└── hypotheses/
    └── powershell-unusual-execution/
        ├── HYPOTHESIS.md       # behavior, sources, design, limitations, false positives
        ├── rule.yml            # the Sigma rule
        ├── generate_events.py  # 22 synthetic Sysmon Event ID 1 events
        ├── events.jsonl        # generated
        └── results.md          # generated test report
```

## Requirements

Python 3.9+. No third-party packages. PyYAML is used automatically if it's installed, but it's
not required.

## Usage

Run the rule tests and write a markdown report:
```bash
python lab.py test powershell-unusual-execution --report
```

Run every hypothesis (useful as a CI gate):
```bash
python lab.py test --all
```

Regenerate the synthetic events after editing `generate_events.py`:
```bash
python lab.py generate powershell-unusual-execution
```

Start a new hypothesis from the templates:
```bash
python lab.py new lsass-memory-access
```

### Commands

| Command | Description |
|---|---|
| `new <name>` | Scaffold `hypotheses/<name>/` from `templates/` |
| `generate <name>` | Run the hypothesis' `generate_events.py` → `events.jsonl` |
| `test <name>` | Evaluate `rule.yml` against `events.jsonl`. Exits 1 on any unexpected result |
| `test --all` | Test every hypothesis |
| `--report` | With `test`, also write `results.md` next to the rule |

## Sample output

```
Rule: Unusual PowerShell Execution - Hidden Encoded Command, Download Cradle, or Office/Script-Host Parent
Condition: selection_img and (all of pattern_a_* or all of pattern_b_* or (selection_parent and 1 of pattern_*)) and not 1 of filter_optional_*

  [PASS] ps-01  true_positive         expect=match    got=match    Word macro launches hidden encoded PowerShell (classic maldoc)
  [PASS] ps-03  true_positive         expect=match    got=match    Slash prefixes and numeric window style (/w 1 /ec)
  [PASS] ps-06  true_positive         expect=match    got=match    Renamed powershell.exe caught through OriginalFileName
  [PASS] ps-13  true_negative         expect=no_match got=no_match -Encoding parameter must not be read as -EncodedCommand
  [PASS] ps-19  known_false_positive  expect=match    got=match    Official Chocolatey install one-liner is a real download cradle
  [PASS] ps-21  known_false_negative  expect=no_match got=no_match String-concatenated cradle with no IEX/WebClient literal
  ...

22/22 cases behave as expected
  true_positive         10
  true_negative         8
  known_false_positive  1
  known_false_negative  3
```

## Running tests

```bash
python -m unittest discover -s tests -v
```

22 tests cover the YAML loader, every supported Sigma modifier, condition precedence and
quantifiers, plus **mutation tests**. These break the rule on purpose and check that exactly the
event guarding that logic fails.

## Design decisions (interview talking points)

- **Combinations, not single flags.** Admins use `-EncodedCommand` and hidden windows on their own
  all the time (SCCM, scheduled tasks). Alerting only when they're combined, or when the parent
  process is suspicious, is what makes the rule high-signal instead of noisy.
- **Regex beats the substring approach used in prior art.** The SigmaHQ rule matches `-enco` as a
  substring, which also hits `-Encoding`. It therefore needs an exclusion, and an attacker can
  append `-Encoding` to slip past it. My regex accepts only real abbreviations of
  `-EncodedCommand` (`-e`, `-ec`, `-en`, `-enc` … `-encodedcommand`), so `-Encoding`, `-ep`, and
  `-ex` are rejected without any exclusion. A mutation test proves the substring version fails.
- **Every dash counts.** Windows PowerShell accepts `/` as well as `-`, and phishing documents
  often turn hyphens into en/em dashes. The rule's character class covers all of them (Sigma's
  `windash` idea).
- **Tests that can fail.** A suite where everything passes proves nothing unless it *can* fail.
  The mutation tests drop the filter, drop the `OriginalFileName` check, and loosen the parent logic,
  and each one breaks exactly one targeted case.
- **Own evaluator, loud on gaps.** `sigma_lite.py` implements the subset of the Sigma spec that
  process-creation rules use (`contains`, `startswith`, `endswith`, `all`, `windash`, `cased`,
  `re` with `i`/`m`/`s`, wildcards, `1 of` / `all of`, `and`/`or`/`not`). Anything else
  (`base64offset`, `cidr`, aggregations) raises an error instead of being silently skipped, so a
  green test always means the rule was really evaluated.
- **Zero dependencies.** It runs on a fresh Python install, including versions PyYAML doesn't ship
  wheels for yet.

## Limitations & detection gaps

- **Command line only.** The rule can't see code assembled inside PowerShell (string concatenation,
  environment variables, stdin, `-File` scripts). Pair it with Script Block Logging (Event ID 4104)
  and AMSI-based detections.
- **Quote insertion evades it.** `"-e"nc` reaches the logged command line and defeats the regex.
  This is the next test case to add.
- **Telemetry matters.** It needs Sysmon Event ID 1, or Security 4688 with command-line auditing
  enabled. 4688 has no `OriginalFileName`, so renamed binaries are missed there.
- **Synthetic ≠ production.** The 22 events prove the logic, not the noise level. Run the rule
  against real telemetry before promoting it past `experimental`.
- **Not a SIEM converter.** To deploy, convert `rule.yml` with
  [sigma-cli / pySigma](https://github.com/SigmaHQ/sigma-cli) for your backend and re-check the
  query. The `–`-style escapes in the regex may need rewriting (e.g. `\x{2013}` for PCRE).

## Safety

All test events are synthetic. Payloads are harmless `Write-Output` strings, and URLs use the
RFC 5737 documentation range (`203.0.113.0/24`) or `example.com`. Nothing in this lab executes
the command lines it describes.

## Possible extensions

- More hypotheses: LSASS memory access, scheduled-task persistence, LOLBin proxy execution
- A GitHub Actions workflow that runs `python lab.py test --all` on every push
- Run a sigma-cli conversion in CI to confirm the rule converts cleanly for Splunk / Elastic / Sentinel
- Replay events from public datasets (e.g. Mordor / Security Datasets) as a noise check
