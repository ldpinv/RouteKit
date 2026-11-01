# RouteKit

Surge / Egern 分流规则，以及自行维护的脚本和模块。真实配置、节点和订阅留在本地。

## 目录

```text
Source/    自定义规则，日常修改这里
List/      自动生成的 Surge 规则
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

文件使用 Surge 规则语法，支持 `DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`、`IP-CIDR6`，不要填写策略名。人工规则优先于上游分类；不同策略的人工规则冲突时停止构建。IP 自动添加 `no-resolve`。

直接在 GitHub 编辑并提交 `Source/` 后，Workflow 校验并生成两端规则。上游每天 **02:23 UTC / 11:23 日本时间** 检查一次，通过 PR 更新，合并后生效；不自动合并。

本地维护使用 Python 3.9+，无需安装依赖：

```sh
python3 .github/routekit.py build
python3 -m unittest discover -s .github
python3 .github/routekit.py check
# 手动获取新的上游版本
python3 .github/routekit.py sync
```

首次构建按固定提交下载上游并校验 SHA256，此后可使用缓存。同步遇到空数据、大幅变化或未审查的 AI 规则类型时不会发布。

## 客户端接入

规则 URL 前缀：

- Surge：`https://raw.githubusercontent.com/ldpinv/RouteKit/main/List/`
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

这些文件分类不增加策略组。`custom/` 中的空产物用于预留固定入口，首次接入后添加自定义规则就不用修改主配置。`reject` 默认为空，不附带大型广告库。完整生成顺序见 [.github/routing-order.json](.github/routing-order.json)。

例如海外 AI 的地址：

- [Surge AI](https://raw.githubusercontent.com/ldpinv/RouteKit/main/List/domains/ai.list)
- [Egern AI](https://raw.githubusercontent.com/ldpinv/RouteKit/main/Egern/domains/ai.yaml)

Surge IP 引用行也建议添加 `no-resolve`；Egern 产物已设置 `no_resolve: true`。修改规则归属后，应刷新涉及的列表并用新连接确认命中；客户端独立缓存多个 URL，不保证同时切换版本。

## 匹配原则

- 海外 AI → AI；国内 AI → Internal。Gemini、Copilot、Apple Intelligence 先于 Google / Apple / 通用规则。
- YouTube、Netflix、Disney+ 等合并到 Streaming，先于 Google。AppleCN 先于 Apple。
- 域名优先、IP 补充；不通过整个共享 CDN 或云平台网段猜测业务。
- `no-resolve` 避免为了匹配 IP 规则主动解析，不等于强制远端 DNS。域名型代理能否由出口解析取决于协议和客户端；WireGuard 等 IP 隧道需另外核验。
- 不在规则集里启用全局扩展匹配、MITM 或逐请求脚本。Google 和 Gemini 共用登录域名时，规则无法按域名区分每次登录意图；需要一致出口时由本地策略选择保证。
- `List/macos-process/ai.list` 是可选的 Mac AI 进程补充；放在本地例外、custom 和国内 AI 域名规则之后。iOS / Egern 不加载它。

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
