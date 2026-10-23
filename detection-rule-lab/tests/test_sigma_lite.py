"""Tests for the evaluator itself, plus mutation checks that prove the rule tests can fail.

Run from the lab root:  python -m unittest discover -s tests -v
"""

import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import lab  # noqa: E402
import yaml_lite  # noqa: E402
from sigma_lite import SigmaRule, UnsupportedSigma  # noqa: E402

PS_RULE = ROOT / "hypotheses" / "powershell-unusual-execution"


def rule(detection):
    return SigmaRule({"title": "t", "detection": detection})


class YamlLiteTests(unittest.TestCase):
    def test_nested_lists_of_maps_and_quotes(self):
        data = yaml_lite.load(
            "a:\n  - X|endswith:\n      - '\\p.exe'\n      - 'it''s'\n  - Y: \"q\"\nb: 3\nc: true # comment\n"
        )
        self.assertEqual(data, {"a": [{"X|endswith": ["\\p.exe", "it's"]}, {"Y": "q"}], "b": 3, "c": True})

    def test_block_scalars(self):
        data = yaml_lite.load("d: |\n  one\n    two\ne: >-\n  x and\n  y\n")
        self.assertEqual(data, {"d": "one\n  two", "e": "x and y"})

    def test_rejects_flow_syntax(self):
        with self.assertRaises(yaml_lite.YamlLiteError):
            yaml_lite.load("a: [1, 2]\n")


class ModifierTests(unittest.TestCase):
    def test_plain_value_is_exact_and_case_insensitive(self):
        r = rule({"s": {"F": "abc"}, "condition": "s"})
        self.assertTrue(r.matches({"F": "ABC"}))
        self.assertFalse(r.matches({"F": "abcd"}))

    def test_wildcards_and_escapes(self):
        r = rule({"s": {"F": "a*c?"}, "condition": "s"})
        self.assertTrue(r.matches({"F": "aXXcZ"}))
        r = rule({"s": {"F": "a\\*"}, "condition": "s"})
        self.assertTrue(r.matches({"F": "a*"}))
        self.assertFalse(r.matches({"F": "ab"}))

    def test_backslash_paths_are_literal(self):
        r = rule({"s": {"F|endswith": "\\powershell.exe"}, "condition": "s"})
        self.assertTrue(r.matches({"F": "C:\\Windows\\PowerShell.exe"}))
        self.assertFalse(r.matches({"F": "C:\\Windows\\notpowershell.exe"}))

    def test_contains_all(self):
        r = rule({"s": {"F|contains|all": ["a", "b"]}, "condition": "s"})
        self.assertTrue(r.matches({"F": "xbxa"}))
        self.assertFalse(r.matches({"F": "xa"}))

    def test_windash(self):
        r = rule({"s": {"F|windash|contains": " -enc "}, "condition": "s"})
        for dash in "-/\u2013\u2014\u2015":
            self.assertTrue(r.matches({"F": f"p {dash}enc x"}), dash)
        self.assertFalse(r.matches({"F": "p +enc x"}))

    def test_cased(self):
        r = rule({"s": {"F|cased": "Abc"}, "condition": "s"})
        self.assertFalse(r.matches({"F": "abc"}))

    def test_regex_is_case_sensitive_unless_i(self):
        self.assertFalse(rule({"s": {"F|re": "^abc$"}, "condition": "s"}).matches({"F": "ABC"}))
        self.assertTrue(rule({"s": {"F|re|i": "^abc$"}, "condition": "s"}).matches({"F": "ABC"}))

    def test_null_and_missing_fields(self):
        r = rule({"s": {"F": None}, "condition": "s"})
        self.assertTrue(r.matches({}))
        self.assertFalse(r.matches({"F": "x"}))
        self.assertFalse(rule({"s": {"F": "x"}, "condition": "s"}).matches({}))

    def test_keyword_list(self):
        r = rule({"k": ["mimikatz"], "condition": "k"})
        self.assertTrue(r.matches({"A": "run Mimikatz now"}))

    def test_unsupported_modifier_raises(self):
        with self.assertRaises(UnsupportedSigma):
            rule({"s": {"F|base64offset|contains": "x"}, "condition": "s"})


class ConditionTests(unittest.TestCase):
    D = {"a": {"F": "1"}, "b": {"G": "1"}, "sel_x": {"H": "1"}, "sel_y": {"I": "1"}}

    def r(self, cond):
        return rule({**self.D, "condition": cond})

    def test_precedence_not_and_or(self):
        r = self.r("a or b and not sel_x")  # a or (b and (not sel_x))
        self.assertTrue(r.matches({"F": "1", "H": "1"}))
        self.assertFalse(r.matches({"G": "1", "H": "1"}))

    def test_parentheses(self):
        self.assertFalse(self.r("(a or b) and sel_x").matches({"F": "1"}))

    def test_quantifiers(self):
        self.assertTrue(self.r("1 of sel_*").matches({"I": "1"}))
        self.assertFalse(self.r("all of sel_*").matches({"I": "1"}))
        self.assertTrue(self.r("all of sel_*").matches({"H": "1", "I": "1"}))
        self.assertTrue(self.r("1 of them").matches({"G": "1"}))

    def test_unknown_identifier_raises(self):
        with self.assertRaises(UnsupportedSigma):
            self.r("a and nope")
        with self.assertRaises(UnsupportedSigma):
            self.r("1 of zzz_*")


class PowerShellRuleTests(unittest.TestCase):
    def test_all_cases_behave_as_expected(self):
        _, rows = lab.run_tests(PS_RULE)
        self.assertEqual([r["id"] for r in rows if not r["ok"]], [])

    def mutated(self, edit):
        """Apply edit() to a copy of the rule and return the IDs of cases that now fail."""
        data = yaml_lite.load((PS_RULE / "rule.yml").read_text(encoding="utf-8"))
        data = copy.deepcopy(data)
        edit(data["detection"])
        r = SigmaRule(data)
        failing = []
        for ev in lab.load_events(PS_RULE / "events.jsonl"):
            fields = {k: v for k, v in ev.items() if k != "_lab"}
            got = "match" if r.matches(fields) else "no_match"
            if got != ev["_lab"]["expect"]:
                failing.append(ev["_lab"]["id"])
        return failing

    def test_mutation_drop_filter(self):
        def edit(d):
            d["condition"] = d["condition"].replace("and not 1 of filter_optional_*", "")
        self.assertEqual(self.mutated(edit), ["ps-18"])

    def test_mutation_naive_encoded_contains(self):
        # The SigmaHQ-style " -enco" substring would also hit -Encoding.
        def edit(d):
            d["pattern_a_encoded"] = {"CommandLine|windash|contains": [" -e ", " -enc", " -ec "]}
        self.assertIn("ps-13", self.mutated(edit))

    def test_mutation_drop_original_file_name(self):
        def edit(d):
            d["selection_img"] = [d["selection_img"][0]]
        self.assertEqual(self.mutated(edit), ["ps-06"])

    def test_mutation_parent_alone_is_enough(self):
        def edit(d):
            d["condition"] = d["condition"].replace("(selection_parent and 1 of pattern_*)", "selection_parent")
        self.assertEqual(self.mutated(edit), ["ps-16"])


if __name__ == "__main__":
    unittest.main()
