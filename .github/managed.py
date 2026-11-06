"""Pinned compatibility lists and ordered DNS exports. No client code is executed."""
import ipaddress
import json
import re


YAML_TYPES = {
    "domain_set": "DOMAIN", "domain_suffix_set": "DOMAIN-SUFFIX",
    "domain_keyword_set": "DOMAIN-KEYWORD", "domain_wildcard_set": "DOMAIN-WILDCARD",
    "domain_regex_set": "DOMAIN-REGEX", "ip_cidr_set": "IP-CIDR",
    "ip_cidr6_set": "IP-CIDR6", "asn_set": "IP-ASN",
    "user_agent_set": "USER-AGENT", "url_regex_set": "URL-REGEX",
}
BASE_URL = "https://raw.githubusercontent.com/ldpinv/RouteKit/main/"


def flat_yaml(text):
    """Accept only the flat, scalar-list ruleset schema used by pinned sources."""
    result, key = {}, None
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped in {"---", "..."}:
            continue
        if stripped == "no_resolve: true":
            continue
        if not line[0].isspace() and re.fullmatch(r"[a-z0-9_]+:\s*(?:\[\])?", line):
            key = line.split(":", 1)[0]
            if key not in YAML_TYPES or key in result:
                raise ValueError("Unknown/duplicate compatibility YAML field: " + key)
            result[key] = []
            continue
        if key is None or not stripped.startswith("- "):
            raise ValueError(f"Compatibility YAML must contain flat lists only (line {number})")
        value = stripped[2:].strip()
        if value.startswith('"'):
            value = json.loads(value)
        elif value.startswith("'"):
            if not value.endswith("'"):
                raise ValueError("Unterminated YAML string")
            value = value[1:-1].replace("''", "'")
        elif any(token in value for token in (" #", "!", "&", "* ", "{", "[")):
            raise ValueError("Unsupported compatibility YAML scalar")
        if not isinstance(value, str) or not value or "\n" in value:
            raise ValueError("Invalid compatibility YAML value")
        result[key].append(value)
    if not result:
        raise ValueError("Empty compatibility YAML")
    return {(YAML_TYPES[key], value) for key, values in result.items() for value in values}


def surge_rows(text, allowed):
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 2 or parts[0] not in allowed:
            raise ValueError("Unexpected compatibility rule type: " + parts[0])
        if parts[0] == "AND":
            # The current source uses flat protocol/domain clauses. New logical
            # structures require review rather than accepting nested downloads.
            match = re.fullmatch(r"AND,\((\([^()]+\)(?:,\s*\([^()]+\))+)\)", line)
            if not match:
                raise ValueError("Unsupported compatibility logical rule")
            for clause in re.findall(r"\(([^()]+)\)", match[1]):
                if clause in {"PROTOCOL,UDP", "PROTOCOL,TCP"}:
                    continue
                surge_rows(clause, {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"})
        elif parts[0] == "URL-REGEX" and len(parts) != 2:
            raise ValueError("Compatibility URL rule with commas needs explicit review")
        if parts[0] in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "IP-CIDR", "IP-CIDR6", "IP-ASN", "USER-AGENT"}:
            if any(option not in {"no-resolve", "extended-matching"} for option in parts[2:]):
                raise ValueError("Policy or unsupported option in compatibility ruleset")
            if parts[0] in {"IP-CIDR", "IP-CIDR6"}:
                ipaddress.ip_network(parts[1], strict=False)
            if parts[0] in {"IP-CIDR", "IP-CIDR6", "IP-ASN"} and "no-resolve" not in parts:
                parts.append("no-resolve")
            line = ",".join(parts)
        # Validated logical/URL rules are preserved, never evaluated here.
        rows.append(line)
    if not rows:
        raise ValueError("Empty compatibility ruleset")
    return list(dict.fromkeys(rows))


def render_flat_yaml(rows, header):
    reverse = {kind: key for key, kind in YAML_TYPES.items()}
    grouped = {}
    for kind, value in sorted(rows):
        if kind not in reverse:
            raise ValueError("Cannot render native Egern compatibility type: " + kind)
        grouped.setdefault(reverse[kind], []).append(value)
    lines = [header.rstrip(), "no_resolve: true"]
    for key, values in grouped.items():
        lines.append(key + ":")
        lines.extend("  - " + json.dumps(value, ensure_ascii=True) for value in values)
    return ("\n".join(lines) + "\n").encode()


def compile_compat(config, blobs):
    outputs, stats, manifest = {}, {}, []
    sources = {source["id"]: source for source in config.get("managed_sources", [])}
    for spec in config.get("managed_outputs", []):
        path, fmt = spec["path"], spec["format"]
        if not re.fullmatch(r"(?:Surge|Egern)/services/[a-z0-9-]+\.(?:list|yaml|txt)", path):
            raise ValueError("Invalid managed output path")
        header = "# RouteKit / managed " + path + "\n# Pinned public sources; provenance and original licenses: https://github.com/ldpinv/RouteKit/blob/main/NOTICE.md\n"
        rows, native = [], set()
        for source_id in spec["sources"]:
            source = sources[source_id]
            text = blobs[source["snapshot"]].decode("utf-8-sig")
            if fmt == "egern":
                if source["format"] != "egern":
                    raise ValueError("Native Egern source expected")
                try:
                    native.update(flat_yaml(text))
                except ValueError as error:
                    raise ValueError(source_id + ": " + str(error)) from error
            elif fmt == "domainset":
                for row in text.splitlines():
                    row = row.strip()
                    if row and not row.startswith(("#", ";", "//")):
                        if not re.fullmatch(r"\.?[a-zA-Z0-9_.*?-]+", row):
                            raise ValueError("Invalid managed domainset")
                        rows.append(row)
            elif fmt == "surge":
                rows.extend(surge_rows(text, source["allowed_types"]))
            else:
                raise ValueError("Unknown managed output format")
        if fmt == "egern":
            outputs[path] = render_flat_yaml(native, header)
            count = len(native)
        else:
            rows = list(dict.fromkeys(rows))
            outputs[path] = (header + "\n".join(rows) + "\n").encode()
            count = len(rows)
        if not count:
            raise ValueError("Empty managed output: " + path)
        stats[path] = count
        manifest.append({"path": path, "policy": spec["policy"], "placement": spec["placement"], "rules": count})
    return outputs, stats, manifest


def compile_dns(root, config, base, overrides, dlc, api):
    """Keep routing precedence; mainland DNS is an explicit source decision."""
    settings = config["dns"]
    domestic = set(settings["domestic_categories"])
    manual = {}
    outputs, sequence = {}, []
    for resolver in ("overseas", "domestic"):
        rules = api.minimize(api.parse_manual(root / "Source" / ("dns-" + resolver + ".list")))
        if any(rule.kind not in {"DOMAIN", "DOMAIN-SUFFIX"} for rule in rules):
            raise ValueError("DNS overrides only accept exact/suffix domain rules")
        manual[resolver] = rules
        path = "Surge/dns/override-" + resolver + ".list"
        outputs[path] = api.render(rules, "dns-" + resolver, "surge")
        sequence.append({"path": path, "resolver": resolver, "rules": len(rules)})
    if any(api.overlaps(a, b) for a in manual["overseas"] for b in manual["domestic"]):
        raise ValueError("Conflicting DNS overrides")

    # This is narrower than the Internal policy: only the explicitly selected
    # mainland-domain source is used, not every reachable/direct service.
    mainland = []
    for kind, value, tags, origin in dlc.resolve(settings["mainland_dlc_list"]):
        if kind not in {"full", "domain"} or "." not in value:
            continue
        mainland.append(api.normalize("DOMAIN" if kind == "full" else "DOMAIN-SUFFIX", value))
    mainland = api.minimize(mainland)
    mainland_path = "Surge/dns/mainland.list"
    outputs[mainland_path] = api.render(mainland, "dns-mainland", "surge")

    for phase, collection in (("custom", overrides), ("domains", base)):
        for category, rules in collection.items():
            if category == "reject":
                continue  # Blocking remains in the routing layer.
            if category == "internal" and phase == "domains":
                sequence.append({"path": mainland_path, "resolver": "domestic", "rules": len(mainland)})
                continue
            domain_rules = [rule for rule in rules if rule.kind in api.DOMAIN_KINDS]
            resolver = "domestic" if category in domestic else "overseas"
            # Keep empty custom endpoints stable for future manual routing edits.
            path = "Surge/" + phase + "/" + category + ".list"
            sequence.append({"path": path, "resolver": resolver, "rules": len(domain_rules)})

    servers = settings["upstreams"]
    surge = ["# RouteKit DNS bindings; merge under [Host] after private host mappings.",
             "# Keep this order. Internal/DIRECT selection alone does not imply mainland DNS.",
             "[Host]"]
    egern = ["# RouteKit DNS forwarding; merge into dns.forward after private DNS exceptions.",
             "# proxy_rule_set accepts Surge/Clash lists; both clients reuse the same public lists.",
             "dns:", "  forward:"]
    for suffix in ("local", "lan", "home.arpa"):
        surge.extend([suffix + " = server:system", "*." + suffix + " = server:system"])
        egern.extend(["    - domain_suffix:", "        match: " + json.dumps(suffix), "        value: system"])
    for entry in sequence:
        url = BASE_URL + entry["path"]
        resolver = entry["resolver"]
        surge.append("RULE-SET:" + url + " = server:" + ",".join(servers[resolver]))
        egern.extend(["    - proxy_rule_set:", "        match: " + url,
                      "        value: " + ("Domestic-DoH" if resolver == "domestic" else "Overseas-DoH"),
                      "        update_interval: 86400"])
    egern.extend(["    - domain_wildcard:", '        match: "*"', "        value: Overseas-DoH"])
    outputs["Surge/dns/forward.conf"] = ("\n".join(surge) + "\n").encode()
    outputs["Egern/dns/forward.yaml"] = ("\n".join(egern) + "\n").encode()
    return outputs, {"default": "overseas", "rules": sequence, "upstreams": servers}


def dns_match(host, dns, outputs, api):
    """Reference classifier for the ordered generated DNS bindings."""
    host = host.lower().rstrip(".")
    if any(host == suffix or host.endswith("." + suffix) for suffix in ("local", "lan", "home.arpa")):
        return "system"
    for entry in dns["rules"]:
        for line in outputs[entry["path"]].decode().splitlines():
            if not line or line.startswith("#"):
                continue
            kind, value, *_ = line.split(",")
            if kind in api.DOMAIN_KINDS and api.domain_match(api.Rule(kind, value), host):
                return entry["resolver"]
    return dns["default"]
