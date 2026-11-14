# RouteKit

Surge / Egern 分流规则，以及自行维护的脚本和模块。真实配置、节点和订阅留在本地。

## 目录

```text
Source/    自定义规则，日常修改这里
Surge/      自动生成的 Surge 规则
Egern/     自动生成的 Egern 规则
Scripts/   独立维护的脚本（目前预留）
Modules/   独立维护的模块（目前预留）
.github/   构建、上游清单、版本锁、测试和 Workflow
```

下载快照和详细构建报告只放在本地 `.cache/`，不上传。客户端只下载规则文件，不运行构建工具。

## 日常使用

在 `Source/<分类>.list` 添加规则，没有文件时直接新建。例如：

```ini
# Source/ai.list
DOMAIN,api.example.org
DOMAIN-SUFFIX,example.ai
```

文件使用 Surge 规则语法，支持 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-WILDCARD`、`IP-CIDR`、`IP-CIDR6`，不要填写策略名。人工通配符后必须保留至少两层固定域名，例如 `*pcdn*.biliapi.net`；不接受 `*.com`、`pcdn.*.net` 等宽泛模式。人工规则优先于上游分类；不同策略的人工规则冲突或通配符存在潜在重叠时停止构建。IP 自动添加 `no-resolve`。

`Source/reject.list` 维护人工屏蔽项；Bilibili PCDN 规则经已有的 `custom/reject` 入口先于普通 Bilibili 规则匹配。Surge 输出 `DOMAIN-WILDCARD`，Egern 输出带引号的 `domain_wildcard_set`。这些规则用于让播放器避开指定的 PCDN 候选源，实际速度和播放回退需在设备上验证；不屏蔽整个 `bilivideo.com` / `bilivideo.cn`。

直接在 GitHub 编辑并提交 `Source/` 后，Workflow 校验并生成两端规则。上游每天 **02:23 UTC** 检查一次，通过 PR 更新，合并后生效；不自动合并。

本地维护使用 Python 3.9+，无需安装依赖：

```sh
python3 .github/routekit.py build
python3 -m unittest discover -s .github
python3 .github/routekit.py check
# 手动获取新的上游版本
python3 .github/routekit.py sync
# 增加来源时，固定新来源，保留已有来源的提交版本
python3 .github/routekit.py pin
```

首次构建按固定提交下载上游并校验 SHA256，此后可使用缓存。同步遇到空数据、大幅变化或未审查的 AI 规则类型时不会发布。

## 更新审核

自动 PR 用中文列出新增、删除、相同规则的分类归属变化和 DNS 变更，展开即可看到具体规则。相同总数不代表内容相同；父域、通配符及规则顺序仍以 Files changed 为准。

同步任务完成构建、测试和校验后，会给生成提交附加绿色 **RouteKit / generated rules** 状态，并链接到对应运行。这个状态只证明该提交的产物通过检查，不代表实际节点连通性或设备测试。

GitHub 当前会要求人工批准由 GITHUB_TOKEN 创建的 PR 工作流；看到 **Approve workflows to run** 时，点击批准后等待独立检查完成，再人工合并。这不是规则测试失败，不应通过自动批准或自动合并掩盖。规则检查任务只有只读权限，发布任务仅在 main 校验成功后运行。

## 额外业务规则

`Surge/services/` 和 `Egern/services/` 统一管理原配置额外引用的 Microsoft、微信、广告等规则，来源与生成关系见 `.github/sources.json` 的 `managed_sources` / `managed_outputs`。它们固定到提交及 SHA256，跟随同一 PR 更新。

Egern Microsoft 取两份原有公开列表的并集再去重，保留独有条目；Surge 合并原有 Microsoft / Microsoft CDN 列表。微信和广告保留两端原本的格式及处理差异。不同客户端的 services 文件不承诺逐条相同。

services 仍放在原配置对应的位置：广告在 custom 之后、AI 之前；微信、钉钉、测速、Microsoft 在 Google 之后、通用分类之前；IP 广告补充在末尾 IP 区域。它们不新增本地策略组。Surge 的 `speedtest.txt` 是 DOMAIN-SET，其余 `.list` 使用 RULE-SET。单独有来源许可约束的 Sukka 国内 IP 文件仍保留外部引用，本轮没有复制它。

## 统一 DNS 分类

- [Surge DNS 片段](Surge/dns/forward.conf)：合并到 `[Host]`，保留私人 Host 映射在前。
- [Egern DNS 片段](Egern/dns/forward.yaml)：合并到 `dns.forward`，保留私人 DNS 例外在前，并保留已有 Domestic-DoH / Overseas-DoH 上游定义。

两个片段按同一优先级引用域名列表，Egern DNS 的 `proxy_rule_set` 支持 Surge/Clash 文本格式，因此直接复用 Surge 列表，避免维护两套 DNS 分类。排序为：本地名称 → DNS 人工覆盖 → 路由人工覆盖 → 业务分类 → 明确的国内域名源 → 海外兜底。AI-CN、Bilibili、AppleCN 使用国内 DNS；海外 AI 等保持海外 DNS。Internal 的 DNS 判断只取明确的国内域名源，不等同于所有可直连服务；手动将海外域名放入 Internal / DIRECT 也不会自动把它送往国内 DNS。

如需单独改变 DNS，在 `Source/dns-domestic.list` 或 `Source/dns-overseas.list` 添加 DOMAIN / DOMAIN-SUFFIX；这些文件只改变 DNS，不改变路由策略。两个 DNS 覆盖文件有冲突时构建失败。首次接入后，已有 DNS 引用地址固定，日常改 Source 即可。

本地名称使用系统 DNS，其他未知域名的本地解析默认使用海外 DNS。`no-resolve` 和代理协议决定是否需要本地解析；这些片段不强制每个代理出口重新解析，也不改变 `proxy_nameservers`。片段是生成的配置参考，不能把整个片段作为普通分流 rule_set 导入。Surge 须使用支持 Host 远程规则集映射的版本；移动端需实际导入验证。

## 客户端接入

规则 URL 前缀：

- Surge：`https://raw.githubusercontent.com/ldpinv/RouteKit/main/Surge/`
- Egern：`https://raw.githubusercontent.com/ldpinv/RouteKit/main/Egern/`

Surge 使用 `RULE-SET` 和 `.list`；Egern 使用原生 `rule_set` 和 `.yaml`。建议每 86400 秒更新。仓库只提供规则，不提供完整代理配置。

先保留本地网络、隧道与 DNS 启动解析所需例外，再依次加载：

1. `custom/` 下全部分类，人工归属优先。
2. `domains/` 下全部分类，按下表顺序。
3. `ip/ai`、`ip/telegram`、`ip/apple`，用于服务网段补充。
4. 本地 `GEOIP,CN` → Internal，使用 `no-resolve`。
5. 本地 `FINAL/default` → **Final**，默认跟随代理；Surge 保留 `dns-failed`。

| 顺序 | 分类 | 本地策略 |
| --- | --- | --- |
| 1 | reject | REJECT |
| 2 | ai-cn | Internal |
| 3 | ai | AI |
| 4 | paypal | PayPal |
| 5 | streaming | Streaming |
| 6 | telegram | Telegram |
| 7 | bilibili | Bilibili |
| 8 | apple-cn | DIRECT |
| 9 | apple | Apple |
| 10 | google | Google |
| 11 | direct | DIRECT |
| 12 | internal | Internal |
| 13 | global | Global |

这些文件分类不增加策略组。`custom/` 中的空产物用于预留固定入口，首次接入后添加自定义规则就不用修改主配置。核心 `domains/reject` 默认为空；原配置的广告列表在 `services/` 中独立维护。完整生成顺序见 [.github/routing-order.json](.github/routing-order.json)。

例如海外 AI 的地址：

- [Surge AI](https://raw.githubusercontent.com/ldpinv/RouteKit/main/Surge/domains/ai.list)
- [Egern AI](https://raw.githubusercontent.com/ldpinv/RouteKit/main/Egern/domains/ai.yaml)

Surge IP 引用行也建议添加 `no-resolve`；Egern 产物已设置 `no_resolve: true`。修改规则归属后，应刷新涉及的列表并用新连接确认命中；客户端独立缓存多个 URL，不保证同时切换版本。

## 匹配原则

- 海外 AI → AI；国内 AI → Internal。Gemini、Copilot、Apple Intelligence 先于 Google / Apple / 通用规则。
- YouTube、Netflix、Disney+ 等合并到 Streaming，先于 Google。AppleCN 先于 Apple。
- 域名优先、IP 补充；不通过整个共享 CDN 或云平台网段猜测业务。
- `no-resolve` 避免为了匹配 IP 规则主动解析，不等于强制远端 DNS。域名型代理能否由出口解析取决于协议和客户端；WireGuard 等 IP 隧道需另外核验。
- 不在规则集里启用全局扩展匹配、MITM 或逐请求脚本。Google 和 Gemini 共用登录域名时，规则无法按域名区分每次登录意图；需要一致出口时由本地策略选择保证。
- `Surge/macos-process/ai.list` 是可选的 Mac AI 进程补充；放在本地例外、custom 和国内 AI 域名规则之后。iOS / Egern 不加载它。

## 上游与许可

| 来源 | 用途 |
| --- | --- |
| [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) | 国内外 AI、Google、Apple、PayPal、流媒体、国内域名等 |
| [SukkaLab/ruleset.skk.moe](https://github.com/SukkaLab/ruleset.skk.moe) / [SukkaW/Surge](https://github.com/SukkaW/Surge) | AI、Apple 分层、流媒体、国内、直连、CDN 补充 |
| [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules) | 国内外 AI 专项域名补充 |
| [OpenAI](https://openai.com/chatgpt-voice.json)、[Telegram](https://core.telegram.org/resources/cidr.txt) | 官方服务 IP 网段 |

来源、排除和转换理由集中在 [.github/sources.json](.github/sources.json)，固定版本和哈希在 [.github/sources.lock.json](.github/sources.lock.json)。构建检查关键业务、AI 覆盖、前后匹配和两端规则一致性；新端点和设备真实流量仍需使用中核验。

仓库采用 [AGPL-3.0](LICENSE)，第三方数据保留原许可和署名，详见 [NOTICE.md](NOTICE.md)。

GitHub Actions 需允许创建 PR：Settings → Actions → General → Allow GitHub Actions to create and approve pull requests。规则更新不添加脚本或模块；它们单独维护。
