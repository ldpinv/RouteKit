# 来源与许可

RouteKit 的构建器、维护文件及原创文档采用 AGPL-3.0-only。合并含 Sukka 数据的产物按 AGPL-3.0 分发；这不改变第三方原始文件各自的许可。固定提交、原始 URL 与 SHA256 见 .github/sources.lock.json。

| 来源 | 用途 | 许可 / 归属 |
| --- | --- | --- |
| [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) | AI、服务、国内域名及完整 include/affiliation 数据 | MIT，保留 下方 MIT 许可 |
| [SukkaLab/ruleset.skk.moe](https://github.com/SukkaLab/ruleset.skk.moe) | Apple 分层、通用/国内/CDN、流媒体与 AI 补充 | AGPL-3.0；源码 [SukkaW/Surge](https://github.com/SukkaW/Surge)，保留 [原 LICENSE](LICENSE) |
| [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules) | 按国内/海外区分的 AI 专项域名补充 | MIT，保留 下方 MIT 许可 |
| [Telegram 官方 CIDR](https://core.telegram.org/resources/cidr.txt) | 官方公开网络地址事实 | Telegram 官方发布；未宣称取得统一 MIT/AGPL 数据授权 |
| [OpenAI 官方语音网段](https://openai.com/chatgpt-voice.json) | 语音服务公开网络地址事实 | OpenAI 官方发布；未宣称取得统一 MIT/AGPL 数据授权 |

没有导入 Sukka 另有许可的 China IP 文件，也没有复制其生成器。使用了 Sukka 已发布的规则产物，本仓库记录产物提交，但不声称已经展开和审计其所有间接上游。

上游快照仅缓存于本地 `.cache/`，干净克隆可按锁定提交重新获取并校验。两份非版本化官方网段原文内嵌于锁文件，便于复现。构建不执行上游程序。转换和排除理由见 `.github/sources.json`。

## v2fly/domain-list-community

```text
MIT License

Copyright (c) 2018-2019 V2Ray

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## VPSDance/ai-proxy-rules

```text
MIT License

Copyright (c) 2026 VPSDance

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
