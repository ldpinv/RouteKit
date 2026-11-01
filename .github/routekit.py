#!/usr/bin/env python3
"""Build policy-free Surge/Egern rule sets from pinned public snapshots (stdlib only)."""
from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import hashlib
import io
import ipaddress
import json
import re
import subprocess
import sys
import tarfile
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOMAIN_KINDS = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"}
IP_KINDS = {"IP-CIDR", "IP-CIDR6"}
SHARED = {
    "amazonaws.com", "cloudfront.net", "azure.com", "azureedge.net", "azurefd.net",
    "windows.net", "blob.core.windows.net", "cloudflare.com", "cloudflare.net",
    "workers.dev", "pages.dev", "vercel.app", "netlify.app", "akamai.net",
    "akamaihd.net", "akamaized.net", "auth0.com", "sentry.io", "datadoghq.com",
    "browser-intake-datadoghq.com", "github.com", "githubusercontent.com",
    "googleapis.com", "gstatic.com", "google.com",
}


def dumps(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def ordered_categories(config):
    order = config["order"]
    if len(set(order)) != len(order) or set(order) != set(config["categories"]):
        raise ValueError("Category order must contain each category exactly once")
    return {name: config["categories"][name] for name in order}


@dataclass(frozen=True, order=True)
class Rule:
    kind: str
    value: str

    def line(self):
        return f"{self.kind},{self.value}" + (",no-resolve" if self.kind in IP_KINDS else "")


def normalize(kind, value):
    if kind in DOMAIN_KINDS:
        value = value.rstrip(".").lower()
        if kind == "DOMAIN-WILDCARD":
            if not re.fullmatch(r"[a-z0-9_.*?-]+", value) or len(value.split(".")) < 3 or not any(c in value for c in "*?"):
                raise ValueError("Use a bounded hostname wildcard")
            return Rule(kind, value)
        value = value.encode("idna").decode("ascii")
        if len(value) > 253 or not value or any(
            not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", p)
            for p in value.split(".")
        ):
            raise ValueError(f"Invalid domain rule: {kind},{value}")
    elif kind in IP_KINDS:
        net = ipaddress.ip_network(value, strict=True)
        if net.version != (4 if kind == "IP-CIDR" else 6):
            raise ValueError("IP version does not match rule type")
        value = str(net)
    else:
        raise ValueError(f"Unsupported rule type: {kind}")
    return Rule(kind, value)


def parents(domain):
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


def domain_match(rule, domain):
    domain = domain.lower().rstrip(".")
    if rule.kind == "DOMAIN-WILDCARD":
        return fnmatch.fnmatchcase(domain, rule.value)
    return domain == rule.value or (rule.kind == "DOMAIN-SUFFIX" and domain.endswith("." + rule.value))


def minimize(rules):
    """Remove only entries fully covered within the same policy/phase."""
    rules = set(rules)
    suffixes = {r.value for r in rules if r.kind == "DOMAIN-SUFFIX"}
    domains = []
    for r in rules:
        if r.kind in DOMAIN_KINDS:
            ancestors = parents(r.value)[1:] if r.kind == "DOMAIN-SUFFIX" else parents(r.value)
            if not any(p in suffixes for p in ancestors):
                domains.append(r)
    for kind in sorted(IP_KINDS):
        nets = [ipaddress.ip_network(r.value) for r in rules if r.kind == kind]
        domains.extend(Rule(kind, str(n)) for n in ipaddress.collapse_addresses(nets))
    return sorted(domains)


class DLC:
    """Resolve the complete snapshot, including incoming affiliations and include filters."""
    def __init__(self, files):
        self.direct = defaultdict(list)
        self.includes = defaultdict(list)
        self.memo = {}
        for name, text in sorted(files.items()):
            for number, line in enumerate(text.splitlines(), 1):
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                tokens = line.split()
                head = tokens[0]
                tags = frozenset(t[1:] for t in tokens[1:] if t.startswith("@"))
                affiliations = [t[1:] for t in tokens[1:] if t.startswith("&")]
                if any(not t.startswith(("@", "&")) for t in tokens[1:]):
                    raise ValueError(f"Unrecognized DLC syntax in {name}:{number}")
                if head.startswith("include:"):
                    if affiliations:
                        raise ValueError("Affiliations on include directives need explicit review")
                    self.includes[name].append((head[8:], tags))
                    continue
                kind, value = head.split(":", 1) if ":" in head else ("domain", head)
                item = (kind, value, tags, f"v2fly/data/{name}:{number}")
                self.direct[name].append(item)
                for target in affiliations:
                    self.direct[target].append(item)
        self.names = set(files) | set(self.direct)

    def resolve(self, name, stack=()):
        if name in stack:
            raise ValueError("Cyclic DLC include: " + " -> ".join((*stack, name)))
        if name not in self.names:
            raise ValueError(f"Missing DLC list: {name}")
        if name in self.memo:
            return self.memo[name]
        result = list(self.direct[name])
        for other, filters in self.includes[name]:
            for item in self.resolve(other, (*stack, name)):
                tags = item[2]
                if all((f[1:] not in tags) if f.startswith("-") else (f in tags) for f in filters):
                    result.append(item)
        self.memo[name] = result
        return result


def parse_manual(path):
    result = []
    if not path.exists():
        return result
    for num, line in enumerate(path.read_text().splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [x.strip() for x in line.split(",")]
        if len(parts) < 2 or parts[0] not in DOMAIN_KINDS | IP_KINDS:
            raise ValueError(f"Invalid manual rule in {path.name}:{num}")
        if parts[2:] not in ([], ["no-resolve"]):
            raise ValueError(f"Unexpected policy/parameter in {path.name}:{num}")
        if parts[2:] and parts[0] not in IP_KINDS:
            raise ValueError("no-resolve belongs on IP rules")
        result.append(normalize(parts[0], parts[1]))
    return result


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "RouteKit/1.0 (+https://github.com/ldpinv/RouteKit)"})
    with urllib.request.urlopen(req, timeout=45) as response:
        data = response.read(25_000_001)
    if not data or len(data) > 25_000_000:
        raise ValueError("Empty or oversized upstream response")
    return data


def repository_head(repository, branch):
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository) or not re.fullmatch(r"[\w./-]+", branch):
        raise ValueError("Invalid repository reference")
    output = subprocess.check_output([
        "git", "ls-remote", "https://github.com/" + repository + ".git", "refs/heads/" + branch
    ], text=True, timeout=45)
    sha = output.split()[0]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Cannot pin upstream commit")
    return sha


def unpack_dlc(archive):
    files = {}
    license_data = None
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for entry in tar:
            parts = entry.name.split("/", 1)
            if len(parts) != 2 or not entry.isfile():
                continue
            path = parts[1]
            if path.startswith("data/") and re.fullmatch(r"data/[a-zA-Z0-9_!.-]+", path):
                if entry.size > 2_000_000:
                    raise ValueError("Oversized DLC file")
                files[path[5:]] = tar.extractfile(entry).read().decode("utf-8")
            elif path == "LICENSE":
                license_data = tar.extractfile(entry).read()
    if len(files) < 100 or not license_data:
        raise ValueError("Incomplete DLC snapshot")
    return dumps(files).encode(), license_data


def acquire(config):
    blobs, records, repos = {}, {}, {}
    for key, item in config["repositories"].items():
        sha = repository_head(item["repository"], item["branch"])
        repos[key] = {**item, "commit": sha}
    repo = repos["v2fly"]
    url = f"https://codeload.github.com/{repo['repository']}/tar.gz/{repo['commit']}"
    archive = fetch(url)
    blobs["vendor/v2fly/data.json"], blobs["vendor/v2fly/LICENSE"] = unpack_dlc(archive)
    records["vendor/v2fly/data.json"] = {"url": url, "archive_sha256": digest(archive)}
    records["vendor/v2fly/LICENSE"] = {"url": f"https://raw.githubusercontent.com/{repo['repository']}/{repo['commit']}/LICENSE"}
    jobs = {}
    for source in config["sources"]:
        if source["format"] == "dlc":
            continue
        if "repository" in source:
            repo = repos[source["repository"]]
            url = f"https://raw.githubusercontent.com/{repo['repository']}/{repo['commit']}/{source['path']}"
        else:
            url = source["url"]
        jobs[source["snapshot"]] = url
    repo = repos["sukka"]
    jobs["vendor/sukka/LICENSE"] = f"https://raw.githubusercontent.com/{repo['repository']}/{repo['commit']}/LICENSE"
    for key, repo in repos.items():
        if key not in {"sukka", "v2fly"}:
            jobs[f"vendor/{key}/LICENSE"] = f"https://raw.githubusercontent.com/{repo['repository']}/{repo['commit']}/LICENSE"
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        pending = {pool.submit(fetch, url): (path, url) for path, url in jobs.items()}
        for future in concurrent.futures.as_completed(pending):
            path, url = pending[future]
            blobs[path] = future.result()
            records[path] = {"url": url}
    for path, blob in blobs.items():
        records[path].update(sha256=digest(blob), bytes=len(blob))
    # Official feeds have no immutable version URL: retain their small public payloads.
    for source in config["sources"]:
        if "url" in source:
            key = source["snapshot"]
            records[key]["content"] = blobs[key].decode("utf-8")
    lock = {"schema": 2, "repositories": repos, "files": records}
    return blobs, lock


def render(rules, category, fmt):
    header = f"# RouteKit / {category}\n# Generated; edit Source/<category>.list. Sources and licenses: https://github.com/ldpinv/RouteKit\n"
    if fmt == "surge":
        return (header + "\n".join(r.line() for r in rules)).rstrip().encode() + b"\n"
    keys = {"DOMAIN": "domain_set", "DOMAIN-SUFFIX": "domain_suffix_set", "DOMAIN-WILDCARD": "domain_wildcard_set", "IP-CIDR": "ip_cidr_set", "IP-CIDR6": "ip_cidr6_set"}
    lines = [header.rstrip(), "no_resolve: true"]
    for kind, key in keys.items():
        values = [r.value for r in rules if r.kind == kind]
        if values:
            lines.append(key + ":")
            lines.extend("  - " + json.dumps(v, ensure_ascii=True) for v in values)
    if not rules:
        lines.append("domain_set: []")
    return ("\n".join(lines) + "\n").encode()


def overlaps(a, b):
    if a.kind in DOMAIN_KINDS and b.kind in DOMAIN_KINDS:
        return ((a.value == b.value) or (a.kind == "DOMAIN-SUFFIX" and domain_match(a, b.value))
                or (b.kind == "DOMAIN-SUFFIX" and domain_match(b, a.value)))
    if a.kind == b.kind and a.kind in IP_KINDS:
        return ipaddress.ip_network(a.value).overlaps(ipaddress.ip_network(b.value))
    return False


def compile_rules(root, blobs, lock):
    config = read_json(root / ".github/sources.json")
    categories = ordered_categories(config)
    exclusions = config["exclusions"]
    excluded = {(e["category"], e["rule"]): e["reason"] for e in exclusions}
    replacements = {(e["category"], e["rule"]): e for e in config["replacements"]}
    raw = defaultdict(set)
    provenance = defaultdict(set)
    omitted = []
    transformed = []
    macos_ai = set()
    dlc = DLC(json.loads(blobs["vendor/v2fly/data.json"]))

    def add(category, kind, value, source, tags=()):
        reason = None
        original = f"{kind},{value}"
        if category == "ai" and kind == "PROCESS-NAME" and not value.lower().endswith(".exe"):
            if not re.fullmatch(r"[a-zA-Z0-9._-]+", value):
                raise ValueError("Unexpected process-name syntax")
            macos_ai.add(value)
        if (category, original) in replacements:
            replacement = replacements[(category, original)]
            for entry in replacement["replace_with"]:
                k, v = entry.split(",", 1)
                r = normalize(k, v)
                raw[category].add(r)
                provenance[(category, r)].add(source)
            transformed.append({**replacement, "source": source})
            return
        if (category, original) in excluded:
            reason = excluded[(category, original)]
        elif kind == "DOMAIN-WILDCARD":
            reason = "Upstream wildcard needs an explicit bounded replacement review"
        elif kind not in DOMAIN_KINDS | IP_KINDS:
            reason = "Unsupported/broad matching type; review for a precise domain equivalent"
        elif kind in DOMAIN_KINDS and "." not in value:
            reason = "Whole TLD / single-label ownership does not identify a business"
        elif category in {"ai", "ai-cn", "paypal", "streaming"} and value.lower() in SHARED:
            reason = "Shared infrastructure; routing the whole provider would capture unrelated services"
        if reason:
            omitted.append({"category": category, "rule": original, "source": source, "reason": reason})
            return
        rule = normalize(kind, value)
        raw[category].add(rule)
        provenance[(category, rule)].add(source)

    for spec in config["sources"]:
        category = spec["category"]
        if spec["format"] == "dlc":
            for name in spec["lists"]:
                for kind, value, tags, source in dlc.resolve(name):
                    add(category, {"full": "DOMAIN", "domain": "DOMAIN-SUFFIX"}.get(kind, kind), value, source, tags)
            continue
        data = blobs[spec["snapshot"]].decode("utf-8-sig")
        if spec["format"] == "voice-json":
            obj = json.loads(data)
            if not isinstance(obj.get("prefixes"), list) or not obj.get("creationTime"):
                raise ValueError("Invalid voice ranges document")
            values = [v for entry in obj["prefixes"] for v in entry.values()]
            if not values:
                raise ValueError("Empty voice ranges")
            for value in values:
                kind = "IP-CIDR6" if ipaddress.ip_network(value).version == 6 else "IP-CIDR"
                add(category, kind, value, spec["id"])
            continue
        count = 0
        for num, line in enumerate(data.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith(("#", ";", "//")):
                continue
            count += 1
            source = f"{spec['id']}:{num}"
            if spec["format"] == "domainset":
                add(category, "DOMAIN-SUFFIX" if line.startswith(".") else "DOMAIN", line.lstrip("."), source)
            elif spec["format"] == "cidr":
                add(category, "IP-CIDR6" if ":" in line else "IP-CIDR", line, source)
            elif spec["format"] == "surge":
                parts = [x.strip() for x in line.split(",")]
                if len(parts) < 2:
                    raise ValueError(f"Invalid upstream row: {source}")
                if parts[0] in DOMAIN_KINDS | IP_KINDS and parts[2:] not in ([], ["no-resolve"]):
                    raise ValueError(f"Unexpected upstream options: {source}")
                if spec.get("domains_only") and parts[0] in IP_KINDS | {"IP-ASN"}:
                    omitted.append({"category": category, "rule": f"{parts[0]},{parts[1]}", "source": source, "reason": "Third-party AI network scope excluded; use the separate official voice CIDRs"})
                else:
                    add(category, parts[0], parts[1], source)
            else:
                raise ValueError("Unknown source format")
        if not count:
            raise ValueError(f"Empty upstream: {spec['id']}")

    overrides, base = {}, {}
    for category in categories:
        base[category] = minimize(raw[category])
        overrides[category] = minimize(parse_manual(root / "Source" / f"{category}.list"))
        if any(r.kind == "DOMAIN-WILDCARD" for r in overrides[category]):
            raise ValueError("Source lists use exact/suffix/IP rules; reviewed upstream wildcards belong in .github/sources.json replacements")
    # A manual override may overlap upstream intentionally; conflicting overrides are errors.
    for i, a in enumerate(categories):
        for b in list(categories)[i + 1:]:
            if categories[a]["policy"] != categories[b]["policy"]:
                if any(overlaps(x, y) for x in overrides[a] for y in overrides[b]):
                    raise ValueError(f"Conflicting overrides: {a} / {b}")

    # Remove completely shadowed base domain rules; retain more general fallbacks.
    exact, suffix = {}, {}
    shadowed = []
    for category, rules in base.items():
        keep = []
        for rule in rules:
            owner = None
            if rule.kind in DOMAIN_KINDS:
                owner = next((suffix[p] for p in parents(rule.value) if p in suffix), None)
                if not owner and rule.kind == "DOMAIN":
                    owner = exact.get(rule.value)
            if owner:
                shadowed.append({"category": category, "rule": rule.line(), "winner": owner})
            else:
                keep.append(rule)
        base[category] = keep
        for rule in keep:
            if rule.kind == "DOMAIN-SUFFIX":
                suffix[rule.value] = category
            elif rule.kind == "DOMAIN":
                exact[rule.value] = category

    outputs, order, stats = {}, [], {}
    for phase, collections in (("custom", overrides), ("domains", base), ("ip", base)):
        for category, all_rules in collections.items():
            rules = all_rules if phase == "custom" else [r for r in all_rules if (r.kind in DOMAIN_KINDS) == (phase == "domains")]
            # IP supplements are only published for categories that need them.
            if phase == "ip" and not rules:
                continue
            stem = f"{phase}/{category}"
            order.append({"path": stem, "policy": categories[category]["policy"], "rules": len(rules), "phase": phase})
            stats[stem] = len(rules)
            outputs[f"Surge/{stem}.list"] = render(rules, category, "surge")
            outputs[f"Egern/{stem}.yaml"] = render(rules, category, "egern")
    order.append({"builtin": "GEOIP,CN", "policy": "Internal", "no_resolve": True})
    order.append({"builtin": "FINAL", "policy": "Final", "dns_failed_surge": True})
    outputs[".github/routing-order.json"] = dumps({"schema": 1, "rules": order, "local_rules_first": True}).encode()
    outputs["Surge/macos-process/ai.list"] = (
        "# Optional Mac-only AI process supplement; do not import on iOS/Egern.\n"
        "# Place after local/override and mainland-AI domain rules; before generic services.\n"
        + "\n".join("PROCESS-NAME," + name for name in sorted(macos_ai)) + "\n"
    ).encode()
    omitted = sorted({json.dumps(x, sort_keys=True): x for x in omitted}.values(), key=lambda x: (x["category"], x["rule"], x["source"]))
    outputs[".cache/reports/omitted.json"] = dumps(omitted).encode()
    outputs[".cache/reports/transforms.json"] = dumps(sorted(transformed, key=lambda x: (x["category"], x["rule"], x["source"]))).encode()
    outputs[".cache/reports/shadowed.json"] = dumps(shadowed).encode()
    outputs[".cache/reports/summary.json"] = dumps({"rules": stats, "omitted": len(omitted), "shadowed": len(shadowed), "raw_unique": {c: len(raw[c]) for c in categories}}).encode()
    def origins(category, rule):
        if rule.kind in IP_KINDS:
            net = ipaddress.ip_network(rule.value)
            sources = set()
            for original in raw[category]:
                if original.kind == rule.kind and ipaddress.ip_network(original.value).subnet_of(net):
                    sources.update(provenance.get((category, original), {"Source/" + category + ".list"}))
            return sorted(sources)
        return sorted(provenance.get((category, rule), {"Source/" + category + ".list"}))
    prov = {c: {r.line(): origins(c, r) for r in base[c]} for c in categories}
    outputs[".cache/reports/provenance.json"] = dumps(prov).encode()
    coverage = {}
    for category in ("ai", "ai-cn"):
        entries = []
        for rule in sorted(raw[category]):
            if rule.kind in DOMAIN_KINDS:
                sample = rule.value.replace("*", "sample").replace("?", "x")
                actual = route(base, overrides, categories, sample)
                intentional = route({c: [] for c in categories}, overrides, categories, sample) != "Final"
                if actual not in {"AI", "Internal"} and not intentional:
                    raise ValueError(f"AI coverage lost: {sample} -> {actual}")
                entries.append({"rule": rule.line(), "policy": actual, "manual_override": intentional})
        coverage[category] = entries
    outputs[".cache/reports/ai-coverage.json"] = dumps(coverage).encode()
    outputs["LICENSE"] = blobs["vendor/sukka/LICENSE"]
    return outputs, base, overrides


def load_snapshots(root):
    lock = read_json(root / ".github/sources.lock.json")
    blobs = {}

    def load_one(name, info):
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or not name.startswith("vendor/"):
            raise ValueError("Invalid snapshot path")
        cached = root / ".cache" / path
        if cached.exists():
            data = cached.read_bytes()
        elif "content" in info:
            data = info["content"].encode("utf-8")
        elif name == "vendor/v2fly/data.json":
            # Validate normalized file content; archive compression metadata may vary.
            data, _ = unpack_dlc(fetch(info["url"]))
        else:
            data = fetch(info["url"])
        if digest(data) != info["sha256"]:
            raise ValueError(f"Snapshot hash mismatch: {name}")
        if not cached.exists():
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(data)
        return name, data

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for name, data in pool.map(lambda item: load_one(*item), lock["files"].items()):
            blobs[name] = data
    return blobs, lock


def write_files(root, outputs, prune=False):
    if prune:
        for directory in ("Surge", "Egern", ".cache/reports"):
            for path in (root / directory).rglob("*") if (root / directory).exists() else ():
                if path.is_file() and path.relative_to(root).as_posix() not in outputs:
                    path.unlink()
    for name, content in outputs.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_bytes(content)
        temporary.replace(path)


def route(base, overrides, categories, host, resolved_ip=None):
    try:
        ip = ipaddress.ip_address(host)
        domain = None
    except ValueError:
        domain = host.lower().rstrip(".")
        ip = ipaddress.ip_address(resolved_ip) if resolved_ip else None
    for phase, groups in (("custom", overrides), ("domains", base), ("ip", base)):
        for category, rules in groups.items():
            for r in rules:
                if r.kind in DOMAIN_KINDS:
                    if phase != "ip" and domain and domain_match(r, domain):
                        return categories[category]["policy"]
                elif phase != "domains" and ip and ip in ipaddress.ip_network(r.value):
                    return categories[category]["policy"]
    # GeoIP is external client data; tests of it are separate from the domain classifier.
    return "Final"


def validate_behavior(root, base, overrides):
    categories = ordered_categories(read_json(root / ".github/sources.json"))
    cases = read_json(root / ".github/cases.json")
    failures = []
    for case in cases:
        actual = route(base, overrides, categories, case["host"], case.get("resolved_ip"))
        explicit = route({c: [] for c in categories}, overrides, categories, case["host"], case.get("resolved_ip"))
        expected = explicit if explicit != "Final" else case["policy"]
        if actual != expected:
            failures.append(f"{case['host']} expected {expected}, got {actual}")
    if failures:
        raise ValueError("Routing regressions: " + "; ".join(failures))
    return len(cases)


def check_public(root):
    allowed = {".git", ".cache", ".gitignore", ".gitattributes", ".github", "AGENTS.md", "README.md", "LICENSE", "NOTICE.md", "Source", "Surge", "Egern", "Scripts", "Modules"}
    extra = {p.name for p in root.iterdir() if p.name != ".DS_Store"} - allowed
    if extra:
        raise ValueError("Unexpected public-root entries: " + ", ".join(sorted(extra)))
    pattern = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|(?:ss|trojan|vmess|vless)://[A-Za-z0-9]")
    for path in root.rglob("*"):
        if path.name == ".DS_Store" or {".git", ".cache", "__pycache__"}.intersection(path.relative_to(root).parts):
            continue
        if path.is_symlink():
            raise ValueError("Symlinks are not allowed in the public tree")
        if path.is_file() and pattern.search(path.read_text(encoding="utf-8")):
            raise ValueError("Potential secret in public tree: " + str(path.relative_to(root)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["sync", "build", "check", "stats"])
    parser.add_argument("--allow-large-change", action="store_true")
    args = parser.parse_args()
    config = read_json(ROOT / ".github/sources.json")
    blobs, lock = load_snapshots(ROOT)
    previous = None
    if args.command == "sync":
        previous, _, _ = compile_rules(ROOT, blobs, lock)
        blobs, lock = acquire(config)
    outputs, base, overrides = compile_rules(ROOT, blobs, lock)
    count = validate_behavior(ROOT, base, overrides)
    if args.command == "stats":
        print(outputs[".cache/reports/summary.json"].decode())
        return
    if previous is not None:
        before = json.loads(previous[".cache/reports/summary.json"])["rules"]
        after = json.loads(outputs[".cache/reports/summary.json"])["rules"]
        changes = {k: [before.get(k, 0), v] for k, v in after.items() if v != before.get(k, 0)}
        print("Rule count changes: " + json.dumps(changes))
        for k, n in before.items():
            if n > 0 and after.get(k, 0) == 0:
                raise ValueError("Unexpected empty ruleset: " + k)
            if n >= 20 and abs(after.get(k, 0) - n) / n > 0.30 and not args.allow_large_change:
                raise ValueError("Large change requires review and --allow-large-change: " + k)
        semantic = [p for p in outputs if p.startswith(("Surge/", "Egern/"))] + [".cache/reports/omitted.json"]
        if all(previous.get(p) == outputs[p] for p in semantic):
            print("No routing/source-filter changes; keep the existing pinned sources.")
            return
    check_public(ROOT)
    if args.command == "check":
        for path, expected in outputs.items():
            if path.startswith(".cache/"):
                continue
            if not (ROOT / path).exists() or (ROOT / path).read_bytes() != expected:
                raise ValueError("Generated file is stale: " + path)
        for folder in ("Surge", "Egern"):
            if any(p.is_file() and p.name != ".DS_Store" and p.relative_to(ROOT).as_posix() not in outputs for p in (ROOT / folder).rglob("*")):
                raise ValueError("Unexpected generated file")
    else:
        if args.command == "sync":
            write_files(ROOT, {**{".cache/" + p: b for p, b in blobs.items()}, ".github/sources.lock.json": dumps(lock).encode()})
        write_files(ROOT, outputs, prune=True)
    print(f"{args.command}: {count} routing cases passed; {sum(len(v) for v in base.values())} upstream rules + {sum(len(v) for v in overrides.values())} custom rules.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"RouteKit: {error}", file=sys.stderr)
        sys.exit(1)
