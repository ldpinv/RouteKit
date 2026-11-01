import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".github"))
import routekit as rk


class RuleSemantics(unittest.TestCase):
    def test_suffix_boundaries_and_case(self):
        rule = rk.Rule("DOMAIN-SUFFIX", "openai.com")
        self.assertTrue(rk.domain_match(rule, "API.OPENAI.COM."))
        self.assertFalse(rk.domain_match(rule, "fakeopenai.com"))
        self.assertFalse(rk.domain_match(rule, "openai.com.evil.example"))

    def test_no_resolve_keeps_unknown_domains_on_final(self):
        categories = {"ai": {"policy": "AI"}}
        base = {"ai": [rk.Rule("IP-CIDR", "203.0.113.0/24")]}
        self.assertEqual(rk.route(base, {"ai": []}, categories, "unlisted.example"), "Final")
        self.assertEqual(rk.route(base, {"ai": []}, categories, "203.0.113.8"), "AI")
        self.assertEqual(rk.route(base, {"ai": []}, categories, "unlisted.example", "203.0.113.8"), "AI")

    def test_domain_decision_precedes_resolved_ip(self):
        base = {"ai": [rk.Rule("DOMAIN", "api.example")], "media": [rk.Rule("IP-CIDR", "203.0.113.0/24")]}
        categories = {"ai": {"policy": "AI"}, "media": {"policy": "Streaming"}}
        self.assertEqual(rk.route(base, {"ai": [], "media": []}, categories, "api.example", "203.0.113.1"), "AI")

    def test_override_precedes_parent_policy(self):
        base = {"google": [rk.Rule("DOMAIN-SUFFIX", "google.com")], "internal": []}
        overrides = {"google": [], "internal": [rk.Rule("DOMAIN", "special.google.com")]}
        categories = {"google": {"policy": "Google"}, "internal": {"policy": "Internal"}}
        self.assertEqual(rk.route(base, overrides, categories, "special.google.com"), "Internal")
        self.assertEqual(rk.route(base, overrides, categories, "www.google.com"), "Google")

    def test_explicit_override_can_change_a_protected_business(self):
        categories = {"ai": {"policy": "AI"}, "direct": {"policy": "DIRECT"}}
        base = {"ai": [rk.Rule("DOMAIN-SUFFIX", "openai.com")], "direct": []}
        overrides = {"ai": [], "direct": [rk.Rule("DOMAIN", "api.openai.com")]}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github").mkdir()
            (root / ".github/sources.json").write_text(json.dumps({"order": list(categories), "categories": categories}))
            (root / ".github/cases.json").write_text(json.dumps([{"host": "api.openai.com", "policy": "AI"}]))
            self.assertEqual(rk.validate_behavior(root, base, overrides), 1)

    def test_minimization_keeps_narrow_boundaries(self):
        rules = [rk.Rule("DOMAIN", "a.example.com"), rk.Rule("DOMAIN-SUFFIX", "example.com"), rk.Rule("DOMAIN", "notexample.com")]
        minimized = rk.minimize(rules)
        self.assertIn(rk.Rule("DOMAIN", "notexample.com"), minimized)
        for host in ["example.com", "a.example.com", "b.a.example.com", "notexample.com", "bad.example.org"]:
            self.assertEqual(any(rk.domain_match(r, host) for r in rules), any(rk.domain_match(r, host) for r in minimized))

    def test_ip_collapsing_does_not_expand_address_space(self):
        rules = [rk.Rule("IP-CIDR", "203.0.113.0/26"), rk.Rule("IP-CIDR", "203.0.113.64/26")]
        self.assertEqual(rk.minimize(rules), [rk.Rule("IP-CIDR", "203.0.113.0/25")])

    def test_include_attributes_and_incoming_affiliations(self):
        dlc = rk.DLC({"ai": "include:child @api @-ads\n", "child": "full:api.example @api\nfull:ads.example @api @ads\n", "unrelated": "other.example &ai\n"})
        self.assertEqual({r[1] for r in dlc.resolve("ai")}, {"api.example", "other.example"})

    def test_include_cycles_and_missing_lists_fail(self):
        with self.assertRaises(ValueError):
            rk.DLC({"a": "include:b", "b": "include:a"}).resolve("a")
        with self.assertRaises(ValueError):
            rk.DLC({"a": "include:missing"}).resolve("a")

    def test_domain_policy_and_invalid_cidr_cannot_enter_lists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.list"
            path.write_text("DOMAIN,example.org,DIRECT\n")
            with self.assertRaises(ValueError):
                rk.parse_manual(path)
        with self.assertRaises(ValueError):
            rk.normalize("IP-CIDR", "203.0.113.7/24")

    def test_bounded_ai_wildcard_does_not_match_other_azure_tenants(self):
        rule = rk.Rule("DOMAIN-WILDCARD", "chatgpt-async-webps-prod-*-*.webpubsub.azure.com")
        self.assertTrue(rk.domain_match(rule, "chatgpt-async-webps-prod-westus-01.webpubsub.azure.com"))
        self.assertFalse(rk.domain_match(rule, "unrelated.webpubsub.azure.com"))
        self.assertFalse(rk.domain_match(rule, "chatgpt-async-webps-prod-x-1.webpubsub.azure.com.evil.example"))


class CompiledRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        blobs, lock = rk.load_snapshots(ROOT)
        cls.outputs, cls.base, cls.overrides = rk.compile_rules(ROOT, blobs, lock)

    def test_business_requests(self):
        self.assertGreaterEqual(rk.validate_behavior(ROOT, self.base, self.overrides), 40)

    def test_client_outputs_preserve_the_same_rules(self):
        for path, data in self.outputs.items():
            if not path.startswith("List/") or "/macos-process/" in path:
                continue
            surge = {line for line in data.decode().splitlines() if line and not line.startswith("#")}
            yaml_path = path.replace("List/", "Egern/").replace(".list", ".yaml")
            yaml = self.outputs[yaml_path].decode().splitlines()
            key = None
            mapped = set()
            kinds = {"domain_set": "DOMAIN", "domain_suffix_set": "DOMAIN-SUFFIX", "domain_wildcard_set": "DOMAIN-WILDCARD", "ip_cidr_set": "IP-CIDR", "ip_cidr6_set": "IP-CIDR6"}
            for line in yaml:
                if line.endswith(":"):
                    key = line[:-1]
                elif line.startswith("  - "):
                    mapped.add(rk.Rule(kinds[key], json.loads(line[4:])).line())
            self.assertEqual(surge, mapped, path)

    def test_all_ip_artifacts_skip_resolution(self):
        for path, data in self.outputs.items():
            if path.startswith("List/"):
                for line in data.decode().splitlines():
                    if line.startswith(("IP-CIDR,", "IP-CIDR6,")):
                        self.assertTrue(line.endswith(",no-resolve"))

    def test_no_unreviewed_ai_drops(self):
        explicit = {(e["category"], e["rule"]) for e in rk.read_json(ROOT / ".github/sources.json")["exclusions"]}
        for item in json.loads(self.outputs[".cache/reports/omitted.json"]):
            if item["category"] in {"ai", "ai-cn"}:
                self.assertIn((item["category"], item["rule"]), explicit, item)

    def test_required_service_precedence(self):
        order = rk.read_json(ROOT / ".github/sources.json")["order"]
        for first, second in [("ai-cn", "ai"), ("ai", "google"), ("ai", "apple-cn"), ("ai", "apple"), ("streaming", "google"), ("apple-cn", "apple"), ("bilibili", "internal")]:
            self.assertLess(order.index(first), order.index(second))


if __name__ == "__main__":
    unittest.main()
