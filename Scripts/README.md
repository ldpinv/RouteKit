# 公开自写脚本

脚本和模块独立于分流规则审查与发布。

## 防火墙自动加白（po0 / guguyun）

在 [Surge 模块](../Modules/Surge/firewall-whitelist.sgmodule) 或 [Egern 模块](../Modules/Egern/firewall-whitelist.yaml) 的参数里填写任意一项，也可以同时填写两项。

- `po0_tokens` 填 po0 防火墙令牌。多个用逗号分隔，可用 `@0` 等后缀指定槽位。
- `guguyun_links` 填 HTTPS 加白分享链接。多个用分号分隔。URL 中的 `&` 原样填写，分号写成 `%3B`。

切换网络后，脚本先等 1 秒，再直连各服务加白。每个首轮成功的服务会在 15 秒后单独确认。每 10 分钟补跑一轮，状态变化时通知。Surge 还支持启动时加白和面板手动刷新，启动事件需要 iOS 5.22+ 或 Mac 6.9+。

两端共用 `firewall-whitelist/core.js`。修改共享逻辑或客户端入口后，运行 `python3 Scripts/firewall-whitelist/build.py` 更新两个独立的客户端脚本，可加 `--check` 核对产物。
