"""Generate synthetic events for this hypothesis. See hypotheses/powershell-unusual-execution for a full example.

Each event needs a "_lab" block: id, expect (match / no_match), category
(true_positive | true_negative | known_false_positive | known_false_negative), and why.
"""

import json
import pathlib
import sys

# (expect, category, why, fields)
CASES = [
    ("match", "true_positive", "Example malicious shape", {"Image": r"C:\Temp\example.exe"}),
    ("no_match", "true_negative", "Example benign shape", {"Image": r"C:\Windows\System32\notepad.exe"}),
]


def main(out_path):
    out = pathlib.Path(out_path)
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for i, (expect, category, why, fields) in enumerate(CASES, start=1):
            event = {"_lab": {"id": f"case-{i:02d}", "expect": expect, "category": category, "why": why}, **fields}
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    print(f"wrote {len(CASES)} events to {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).with_name("events.jsonl"))
