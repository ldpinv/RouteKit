import json
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".github"))
import routekit as rk
import managed
import review


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

    def test_manual_wildcards_require_a_fixed_domain_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reject.list"
            path.write_text("DOMAIN-WILDCARD,*pcdn*.biliapi.net\n")
            self.assertEqual(rk.parse_manual(path), [rk.Rule("DOMAIN-WILDCARD", "*pcdn*.biliapi.net")])
            for pattern in ["*.com", "pcdn.*.net", "*pcdn*.*.*", "*pcdn*..net"]:
                with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                    path.write_text("DOMAIN-WILDCARD," + pattern + "\n")
                    rk.parse_manual(path)

    def test_manual_wildcard_conflicts_stop_the_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github").mkdir()
            (root / "Source").mkdir()
            config = {
                "order": ["reject", "bilibili"],
                "categories": {"reject": {"policy": "REJECT"}, "bilibili": {"policy": "Bilibili"}},
                "sources": [], "exclusions": [], "replacements": [],
            }
            (root / ".github/sources.json").write_text(json.dumps(config))
            (root / "Source/reject.list").write_text("DOMAIN-WILDCARD,*pcdn*.biliapi.net\n")
            for other in ["DOMAIN,edge-pcdn.biliapi.net", "DOMAIN-SUFFIX,biliapi.net", "DOMAIN-WILDCARD,*edge*.biliapi.net"]:
                (root / "Source/bilibili.list").write_text(other + "\n")
                with self.subTest(other=other), self.assertRaisesRegex(ValueError, "Conflicting overrides"):
                    rk.compile_rules(root, {"vendor/v2fly/data.json": b"{}"}, {})
        wildcard = rk.Rule("DOMAIN-WILDCARD", "*pcdn*.biliapi.net")
        for other in [rk.Rule("DOMAIN", "api.biliapi.net"), rk.Rule("DOMAIN-SUFFIX", "other-biliapi.net")]:
            self.assertFalse(rk.overlaps(wildcard, other))
            self.assertFalse(rk.overlaps(other, wildcard))


class CompiledRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        blobs, lock = rk.load_snapshots(ROOT)
        cls.outputs, cls.base, cls.overrides = rk.compile_rules(ROOT, blobs, lock)

    def test_business_requests(self):
        self.assertGreaterEqual(rk.validate_behavior(ROOT, self.base, self.overrides), 40)

    def test_bilibili_pcdn_blocking_preserves_regular_cdn(self):
        categories = rk.ordered_categories(rk.read_json(ROOT / ".github/sources.json"))
        cases = {
            "pcdn.biliapi.net": "REJECT", "foo-PCDN-01.biliapi.net.": "REJECT",
            "mcdn.bilivideo.cn": "REJECT", "video.mcdn.bilivideo.com": "REJECT",
            "node.szbdyd.com": "REJECT", "node.mountaintoys.cn": "REJECT",
            "api.biliapi.net": "Bilibili", "www.bilibili.com": "Bilibili",
            "upos-sz-mirrorali.bilivideo.com": "Bilibili",
            "upos-sz-mirrorali.bilivideo.cn": "Bilibili", "notmcdn.bilivideo.com": "Bilibili",
            "foo-pcdn.biliapi.net.evil.example": "Final", "notszbdyd.com": "Final",
            "mountaintoys.cn.evil.example": "Final", "pcdn.example.org": "Final",
        }
        for host, expected in cases.items():
            with self.subTest(host=host):
                self.assertEqual(rk.route(self.base, self.overrides, categories, host), expected)

    def test_apple_routing_layers(self):
        # Direct assertions also catch accidental manual overrides; the general
        # behavior validator intentionally permits explicit custom policy moves.
        categories = rk.ordered_categories(rk.read_json(ROOT / ".github/sources.json"))
        groups = {
            "AI": ["apple-relay.apple.com", "apple-relay.cloudflare.com",
                   "apple-relay.fastly-edge.com", "cp4.cloudflare.com", "gspe1-ssl.ls.apple.com"],
            "DIRECT": ["www.apple.com.cn", "setup.icloud.com.cn", "gateway.apzones.com",
                       "api.smoot.apple.cn", "cn.ls.apple.com", "gs-loc-cn.apple.com",
                       "cn-smp-paymentservices.apple.com", "cdn-cn1.apple-mapkit.com",
                       "cl2-cn.apple.com", "gsp4-cn.ls.apple.com.edgekey.net.globalredir.akadns.net",
                       "gspe19-2-cn-ssl.ls-apple.com.akadns.net", "mesu-china.apple.com.akadns.net"],
            "Apple": ["www.apple.com", "swcdn.apple.com", "swscan.apple.com", "mesu.apple.com",
                      "appldnld.apple.com", "updates.cdn-apple.com", "download.developer.apple.com",
                      "play.itunes.apple.com", "apps.mzstatic.com", "amp-api.music.apple.com",
                      "amp-api.media.apple.com", "ocsp.apple.com", "valid.apple.com",
                      "guzzoni.apple.com", "probe.siri.apple.com", "gs-loc.apple.com",
                      "weatherkit.apple.com", "configuration.apple.com", "account.apple.com",
                      "setup.icloud.com", "courier.push.apple.com", "mask.icloud.com",
                      "tv.apple.com", "news.apple.com", "appleintelligencefeedback.care.apple.com",
                      "app-site-association.networking.apple", "appletvapp.apple"],
            "Final": ["notapzones.com", "apzones.com.attacker.example",
                      "networking.apple.attacker.example", "unrelated.apple",
                      "swcdn.apple.com.attacker.example"],
        }
        for expected, hosts in groups.items():
            for host in hosts:
                with self.subTest(host=host):
                    self.assertEqual(rk.route(self.base, self.overrides, categories, host), expected)

    def test_apple_cdn_dns_does_not_choose_the_route(self):
        dns = json.loads(self.outputs[".github/routing-order.json"])["dns"]
        categories = rk.ordered_categories(rk.read_json(ROOT / ".github/sources.json"))
        for host in ["swcdn.apple.com", "updates.cdn-apple.com", "mesu.apple.com",
                     "download.developer.apple.com", "play.itunes.apple.com",
                     "amp-api.music.apple.com", "apps.mzstatic.com"]:
            with self.subTest(host=host):
                self.assertEqual(rk.route(self.base, self.overrides, categories, host), "Apple")
                self.assertEqual(managed.dns_match(host, dns, self.outputs, rk), "domestic")
        for host in ["apple-relay.apple.com", "apple-relay.cloudflare.com", "apple-relay.fastly-edge.com",
                     "cp4.cloudflare.com", "gspe1-ssl.ls.apple.com", "account.apple.com",
                     "mask.icloud.com", "guzzoni.apple.com", "gs-loc.apple.com",
                     "weatherkit.apple.com", "app-site-association.networking.apple"]:
            with self.subTest(host=host):
                self.assertEqual(managed.dns_match(host, dns, self.outputs, rk), "overseas")
        for host in ["setup.icloud.com.cn", "gateway.apzones.com", "cn.ls.apple.com",
                     "cdn-cn1.apple-mapkit.com", "cn-smp-paymentservices.apple.com"]:
            with self.subTest(host=host):
                self.assertEqual(managed.dns_match(host, dns, self.outputs, rk), "domestic")

    def test_domestic_dns_overrides_cannot_capture_ai(self):
        domestic = rk.parse_manual(ROOT / "Source/dns-domestic.list")
        protected = [r for c in (self.base, self.overrides) for r in c["ai"] if r.kind in rk.DOMAIN_KINDS]
        for override in domestic:
            for ai_rule in protected:
                self.assertFalse(rk.overlaps(override, ai_rule), (override, ai_rule))

    def test_client_outputs_preserve_the_same_rules(self):
        for path, data in self.outputs.items():
            if not path.startswith("Surge/") or any(part in path for part in ("/macos-process/", "/services/", "/dns/")):
                continue
            surge = {line for line in data.decode().splitlines() if line and not line.startswith("#")}
            yaml_path = path.replace("Surge/", "Egern/").replace(".list", ".yaml")
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
            if path.startswith("Surge/"):
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

    def test_dns_preserves_business_precedence_and_unknown_default(self):
        dns = json.loads(self.outputs[".github/routing-order.json"])["dns"]
        cases = {
            "api.openai.com": "overseas", "gemini.google.com": "overseas",
            "generativelanguage.googleapis.com": "overseas", "api.githubcopilot.com": "overseas",
            "www.youtube.com": "overseas", "www.paypal.com": "overseas",
            "api.deepseek.com": "domestic", "www.doubao.com": "domestic",
            "www.bilibili.com": "domestic", "gs-loc.apple.com": "overseas",
            "www.baidu.com": "domestic", "unlisted-routekit.example": "overseas",
            "printer.home.arpa": "system", "router.lan": "system", "printer.local": "system",
            "openai.com.attacker.example": "overseas",
        }
        for host, expected in cases.items():
            self.assertEqual(managed.dns_match(host, dns, self.outputs, rk), expected, host)

    def test_dns_exports_share_the_same_order(self):
        manifest = json.loads(self.outputs[".github/routing-order.json"])["dns"]
        urls = [managed.BASE_URL + row["path"] for row in manifest["rules"]]
        surge = self.outputs["Surge/dns/forward.conf"].decode()
        egern = self.outputs["Egern/dns/forward.yaml"].decode()
        self.assertEqual([line.split(" = ", 1)[0][9:] for line in surge.splitlines() if line.startswith("RULE-SET:")], urls)
        self.assertEqual([line.strip()[7:] for line in egern.splitlines() if line.strip().startswith("match: https://")], urls)
        for path, data in self.outputs.items():
            if path.startswith("Surge/dns/") and path.endswith(".list"):
                self.assertFalse(any(line.startswith(("IP-", "GEOIP", "DOMAIN-KEYWORD")) for line in data.decode().splitlines()))

    def test_managed_egern_merges_preserve_every_source_rule(self):
        config = rk.read_json(ROOT / ".github/sources.json")
        blobs, _ = rk.load_snapshots(ROOT)
        sources = {s["id"]: s for s in config["managed_sources"]}
        for output in config["managed_outputs"]:
            if output["format"] != "egern":
                continue
            expected = set()
            for source in output["sources"]:
                expected.update(managed.flat_yaml(blobs[sources[source]["snapshot"]].decode()))
            actual = managed.flat_yaml(self.outputs[output["path"]].decode())
            self.assertEqual(actual, expected, output["path"])


class ReviewAndManagedRules(unittest.TestCase):
    def test_changed_lock_refetches_stale_cache_and_checks_new_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / ".github").mkdir(); (root / ".cache/vendor/test").mkdir(parents=True)
            cached = root / ".cache/vendor/test/rules.list"
            cached.write_bytes(b"old rules")
            expected = b"new rules"
            lock = {"files": {"vendor/test/rules.list": {"url": "https://example.org/pinned", "sha256": rk.digest(expected)}}}
            (root / ".github/sources.lock.json").write_text(json.dumps(lock))
            with patch.object(rk, "fetch", return_value=expected) as fetch:
                blobs, _ = rk.load_snapshots(root)
                fetch.assert_called_once()
                self.assertEqual(blobs["vendor/test/rules.list"], expected)
                self.assertEqual(cached.read_bytes(), expected)
            with patch.object(rk, "fetch", side_effect=AssertionError("valid cache must be reused")):
                rk.load_snapshots(root)

    def test_same_count_replacement_is_visible(self):
        old = {"Surge/domains/ai.list": b"DOMAIN,old.example\n"}
        new = {"Surge/domains/ai.list": b"DOMAIN,new.example\n"}
        cfg = {"categories": {"ai": {"policy": "AI"}}}
        report = review.compare(old, new, cfg, cfg)
        self.assertEqual(report["changes"][0]["added"], ["DOMAIN,new.example"])
        self.assertEqual(report["changes"][0]["removed"], ["DOMAIN,old.example"])
        body = review.markdown(report, "base", "head")
        self.assertIn("+DOMAIN,new.example", body)
        self.assertIn("-DOMAIN,old.example", body)

    def test_policy_move_with_unchanged_totals_is_reported(self):
        old = {"Surge/domains/ai.list": b"DOMAIN,a.example\n", "Surge/domains/internal.list": b"DOMAIN,b.example\n"}
        new = {"Surge/domains/ai.list": b"DOMAIN,b.example\n", "Surge/domains/internal.list": b"DOMAIN,a.example\n"}
        cfg = {"categories": {"ai": {"policy": "AI"}, "internal": {"policy": "Internal"}}}
        report = review.compare(old, new, cfg, cfg)
        self.assertEqual(len(report["policy_changes"]), 2)
        self.assertEqual(report["policy_changes"][0]["from"], ["AI"])
        self.assertEqual(report["policy_changes"][0]["to"], ["Internal"])

    def test_adding_lower_priority_overlap_is_not_claimed_as_a_move(self):
        old = {"Surge/domains/ai.list": b"DOMAIN,a.example\n"}
        new = {**old, "Surge/domains/global.list": b"DOMAIN,a.example\n"}
        cfg = {"categories": {"ai": {"policy": "AI"}, "global": {"policy": "Global"}}}
        report = review.compare(old, new, cfg, cfg)
        self.assertEqual(report["policy_changes"], [])

    def test_unchanged_surge_cannot_mask_egern_policy_move(self):
        old = {"Surge/services/microsoft.list": b"DOMAIN,a.example\n",
               "Egern/services/microsoft.yaml": b'domain_set:\n  - "a.example"\n'}
        new = {"Surge/services/microsoft.list": old["Surge/services/microsoft.list"],
               "Egern/services/wechat.yaml": old["Egern/services/microsoft.yaml"]}
        cfg = {"managed_outputs": [{"path": path, "policy": "DIRECT" if "wechat" in path else "Global"}
                                    for path in set(old) | set(new)]}
        moves = review.compare(old, new, cfg, cfg)["policy_changes"]
        self.assertEqual(moves, [{"client": "Egern", "rule": "DOMAIN,a.example", "from": ["Global"], "to": ["DIRECT"]}])

    def test_dns_changes_are_not_counted_as_business_rules(self):
        old = {"Surge/dns/forward.conf": b"old\n"}
        new = {"Surge/dns/forward.conf": b"new\n"}
        report = review.compare(old, new, {}, {})
        self.assertFalse(report["changes"])
        self.assertEqual(report["dns_or_process_files"], ["Surge/dns/forward.conf"])

    def test_native_rules_cannot_inject_yaml_objects(self):
        with self.assertRaises(ValueError):
            managed.flat_yaml("domain_set:\n  - !!python/object:bad {}\n")
        with self.assertRaises(ValueError):
            managed.flat_yaml("domain_set:\n  - example.org\nunknown_set:\n  - x\n")
        self.assertEqual(managed.flat_yaml('domain_set:\n  - "example.org"\nno_resolve: true\n'), {("DOMAIN", "example.org")})

    def test_managed_rules_reject_nested_sources_and_policy_injection(self):
        with self.assertRaises(ValueError):
            managed.surge_rows("DOMAIN,example.org,DIRECT", {"DOMAIN"})
        with self.assertRaises(ValueError):
            managed.surge_rows("RULE-SET,https://unreviewed.example/rules", {"DOMAIN"})
        for row in ["AND,((PROTOCOL,UDP),(RULE-SET,https://unreviewed.example/rules))",
                    "AND,((PROTOCOL,UDP),(DOMAIN,example.org)),DIRECT",
                    "URL-REGEX,^https://example.org/,DIRECT"]:
            with self.assertRaises(ValueError):
                managed.surge_rows(row, {"AND", "URL-REGEX"})
        row = "AND,((PROTOCOL,UDP), (DOMAIN-SUFFIX,googlevideo.com))"
        self.assertEqual(managed.surge_rows(row, {"AND"}), [row])
        self.assertEqual(managed.surge_rows("IP-CIDR,203.0.113.0/24", {"IP-CIDR"}), ["IP-CIDR,203.0.113.0/24,no-resolve"])

    def test_large_review_retains_counts_within_github_body_limit(self):
        rules = ["DOMAIN," + ("x" * 150) + str(i) + ".example" for i in range(60)]
        new = {f"Surge/services/list-{i}.list": ("\n".join(rules) + "\n").encode() for i in range(20)}
        body = review.markdown(review.compare({}, new, {}, {}), "base", "head")
        self.assertLess(len(body), 60000)
        self.assertIn("新增 **1200** 条", body)
        self.assertIn("具体规则请查看 Files changed", body)

    def test_internal_override_does_not_imply_mainland_dns(self):
        config = {"dns": {"domestic_categories": ["ai-cn"], "mainland_dlc_list": "cn",
                          "upstreams": {"domestic": ["https://dns.alidns.com/dns-query"], "overseas": ["https://dns.google/dns-query"]}}}
        base = {"ai-cn": [], "ai": [], "internal": [rk.Rule("DOMAIN-SUFFIX", "example.org")]}
        overrides = {"ai-cn": [], "ai": [], "internal": [rk.Rule("DOMAIN", "foreign.example.org")]}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outputs, dns = managed.compile_dns(root, config, base, overrides, rk.DLC({"cn": "example.org"}), rk)
            for phase, groups in (("custom", overrides), ("domains", base)):
                for category, rules in groups.items():
                    outputs[f"Surge/{phase}/{category}.list"] = rk.render(rules, category, "surge")
            self.assertEqual(managed.dns_match("foreign.example.org", dns, outputs, rk), "overseas")
            self.assertEqual(managed.dns_match("www.example.org", dns, outputs, rk), "domestic")

    def test_dns_override_conflicts_fail(self):
        config = {"dns": {"domestic_categories": [], "mainland_dlc_list": "cn", "upstreams": {}}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "Source").mkdir()
            (root / "Source/dns-domestic.list").write_text("DOMAIN-SUFFIX,example.org\n")
            (root / "Source/dns-overseas.list").write_text("DOMAIN,api.example.org\n")
            with self.assertRaises(ValueError):
                managed.compile_dns(root, config, {}, {}, rk.DLC({"cn": "example.org"}), rk)


if __name__ == "__main__":
    unittest.main()
