#!/usr/bin/env python3
"""Explain public rule changes without executing either revision's code."""
import argparse
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

from managed import flat_yaml

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def rule_lines(path, data):
    if "/dns/" in path or "/macos-process/" in path:
        return set()  # Report bindings/process changes separately, never as domains.
    text = data.decode("utf-8")
    if path.endswith(".yaml"):
        return {kind + "," + value for kind, value in flat_yaml(text)}
    lines = {line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith(("#", "//", ";"))}
    if path.endswith(".txt"):
        return {("DOMAIN-SUFFIX," + line[1:]) if line.startswith(".") else "DOMAIN," + line for line in lines}
    return lines


def label_policy(path, config):
    parts = path.split("/")
    if len(parts) == 3 and parts[1] in {"custom", "domains", "ip"}:
        return config.get("categories", {}).get(parts[2].split(".")[0], {}).get("policy", "unknown")
    for item in config.get("managed_outputs", []):
        if item["path"] == path:
            return item["policy"]
    return "unknown"


def compare(before, after, old_config, new_config):
    changes, special = [], []
    old_owners, new_owners = defaultdict(set), defaultdict(set)
    for path in sorted(set(before) | set(after)):
        old, new = before.get(path, b""), after.get(path, b"")
        if "/dns/" in path or "/macos-process/" in path:
            if old != new:
                special.append(path)
            continue
        previous = rule_lines(path, old) if old else set()
        current = rule_lines(path, new) if new else set()
        old_policy, new_policy = label_policy(path, old_config), label_policy(path, new_config)
        client = path.split("/", 1)[0]
        for line in previous:
            old_owners[(client, line)].add(old_policy)
        for line in current:
            new_owners[(client, line)].add(new_policy)
        # Count mirrored core lists once, but track ownership per client so a
        # change in Egern cannot be hidden by an unchanged Surge service list.
        if path.startswith("Egern/") and "/services/" not in path:
            continue
        added, removed = sorted(current - previous), sorted(previous - current)
        if added or removed or (previous and old_policy != new_policy):
            changes.append({"path": path, "policy": new_policy, "before": len(previous), "after": len(current),
                            "added": added, "removed": removed, "previous_policy": old_policy})
    moves = [{"client": key[0], "rule": key[1], "from": sorted(old_owners[key]), "to": sorted(new_owners[key])}
             for key in sorted(set(old_owners) & set(new_owners))
             if old_owners[key] - new_owners[key]]
    return {"changes": changes, "policy_changes": moves, "dns_or_process_files": special}


def markdown(report, base, head, run_url=None):
    changes = report["changes"]
    added = sum(len(item["added"]) for item in changes)
    removed = sum(len(item["removed"]) for item in changes)
    policies = sorted({item["policy"] for item in changes})
    lines = ["## 更新概要", "", f"比较基线 `{base}` → 待审提交 `{head}`。", "",
             f"- 新增 **{added}** 条，删除 **{removed}** 条；Surge/Egern 共用的核心列表只统计一次。",
             "- 涉及策略：" + ("、".join(policies) if policies else "核心路由未变化") + "。",
             f"- 检测到 **{len(report['policy_changes'])}** 项客户端规则失去原策略归属的变化；最终命中仍取决于顺序。",
             "- 规则总数相同也可能有替换；父域、通配符和顺序变化仍需查看 Files changed。", ""]
    if run_url:
        lines += [f"本提交已在[同步任务]({run_url})中通过生成、回归测试、双端格式和确定性校验。",
                  "PR 的绿色 `RouteKit / generated rules` 状态对应此提交；它不等于设备连通性实测。", "",
                  "GitHub 可能另显示 **Approve workflows to run**：这是 GITHUB_TOKEN 创建 PR 的审批机制。",
                  "如需运行独立的 PR 构建，先批准工作流并等待通过，再人工合并。不会自动批准或合并。", ""]
    if changes:
        lines += ["| 规则文件 | 策略 | 原数量 → 新数量 | 新增 | 删除 |", "| --- | --- | ---: | ---: | ---: |"]
        lines += [f"| `{item['path']}` | {item['policy']} | {item['before']} → {item['after']} | {len(item['added'])} | {len(item['removed'])} |" for item in changes]
        lines += ["", "## 具体变化", ""]
        for item in changes:
            lines += [f"<details><summary>{item['path']}</summary>", "", "```diff"]
            for marker, key in (("-", "removed"), ("+", "added")):
                lines += [marker + rule for rule in item[key][:30]]
                if len(item[key]) > 30:
                    lines.append(f"# 另有 {len(item[key]) - 30} 条，见 Files changed")
            lines += ["```", "", "</details>", ""]
    if report["policy_changes"]:
        lines += ["## 策略归属变化", "", "| 客户端 | 规则 | 原策略 | 新策略 |", "| --- | --- | --- | --- |"]
        lines += [f"| {item['client']} | `{item['rule']}` | {' / '.join(item['from'])} | {' / '.join(item['to'])} |" for item in report["policy_changes"][:30]]
        lines.append("")
    if report["dns_or_process_files"]:
        lines += ["## DNS / 进程补充变化", ""]
        lines += ["- `" + path + "`" for path in report["dns_or_process_files"]]
        lines += ["", "DNS 分类与业务出口选择是两回事；分类顺序或 DNS 上游变化请单独核对。", ""]
    lines += ["合并后等待 main 构建成功，再刷新相关远程列表并用新连接检查命中。", ""]
    body = "\n".join(lines)
    if len(body) > 60000:
        # GitHub PR bodies have a size limit. Keep counts and ownership changes,
        # and let Files changed carry the full diff for unusually large updates.
        body = re.sub(r"## 具体变化\n.*?(?=\n## |\n合并后)",
                      "## 具体变化\n\n本次变更较多，具体规则请查看 Files changed；上方统计保留完整数量。\n",
                      body, flags=re.S)
    return body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head", default="working-tree")
    parser.add_argument("--run-url")
    parser.add_argument("--output", default=".cache/update-pr.md")
    args = parser.parse_args()
    base = git("rev-parse", "--verify", args.base_ref + "^{commit}").decode().strip()
    paths = git("ls-tree", "-r", "--name-only", base, "--", "Surge", "Egern").decode().splitlines()
    before = {path: git("show", base + ":" + path) for path in paths}
    after = {path.relative_to(ROOT).as_posix(): path.read_bytes() for folder in ("Surge", "Egern")
             for path in (ROOT / folder).rglob("*") if path.is_file()}
    old_config = json.loads(git("show", base + ":.github/sources.json"))
    new_config = json.loads((ROOT / ".github/sources.json").read_text())
    report = compare(before, after, old_config, new_config)
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown(report, base[:7], args.head, args.run_url))
    detail = ROOT / ".cache/reports/review.json"
    detail.parent.mkdir(parents=True, exist_ok=True)
    detail.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(f"Review: {len(report['changes'])} changed rulesets, {len(report['policy_changes'])} ownership changes")


if __name__ == "__main__":
    main()
