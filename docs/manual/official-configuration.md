---
title: 官方多平台完整配置
description: Windows、macOS、Linux 和 Android 共用的订阅、策略组、规则集、DNS 与 TUN 配置
---

# 官方多平台完整配置

[`examples/official/multi-platform.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/official/multi-platform.yaml)
是项目维护的完整客户端基线。它不是字段展览，而是能够通过配置编译器、启动远程
订阅、刷新规则集并进入运行时的正式示例。

配置默认从仓库拉取
[`provider-demo.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/official/provider-demo.yaml)。
该订阅只提供 Direct 节点，所以克隆仓库后无需私人凭据即可验证完整数据流。它不是
免费代理服务。需要代理时，把 `feeds.primary.url` 换成自己的订阅地址。

## 已覆盖的功能

| 部分 | 官方配置内容 |
| --- | --- |
| 平台 | Windows、macOS、Linux、Android root TUN、Android VpnService |
| 订阅 | HTTPS 拉取、定时更新、响应大小限制、请求头、过滤、重命名、磁盘缓存 |
| 策略组 | manual、smart、fast、stable、spread |
| 分流 | 域名、IP、网络、端口、进程、协议嗅探、最终规则 |
| 规则集 | 23 个远程 MRS 集合和 1 个内联集合 |
| DNS | 国内与公共服务组、多出口、自适应选择、Fallback、策略和 Fake IP |
| 接管 | 双栈 TUN、自动路由、DNS 劫持、LAN 保留、EIM NAT |
| 管理 | 本机 Mixed 端口、本机面板、原生 API、Clash 兼容 API、Smart 解释 |

## 直接使用

推荐使用默认 `standard` 组件集构建。自定义精简构建至少需要保留配置中实际使用的
`with_tun`、订阅协议和节点协议组件，否则 `check` 会明确报告缺失的编译组件。

Linux 和 macOS：

```bash
cp examples/official/multi-platform.yaml config.yaml
./wuther-core check config.yaml
./wuther-core feeds refresh config.yaml --cache-dir data/feeds
./wuther-core ruleset refresh config.yaml --cache-dir data/rulesets
sudo ./wuther-core run -c config.yaml
```

Windows PowerShell：

```powershell
Copy-Item examples\official\multi-platform.yaml config.yaml
.\wuther-core.exe check config.yaml
.\wuther-core.exe feeds refresh config.yaml --cache-dir data\feeds
.\wuther-core.exe ruleset refresh config.yaml --cache-dir data\rulesets
.\wuther-core.exe run -c config.yaml
```

Windows 启动 TUN 时需要管理员权限。Linux 与 macOS 需要 root 或等效网络能力。
只使用本地 Mixed 代理时，可以先把 `capture.on` 改成 `false`。

## 替换远程订阅

只修改这一项即可接入自己的 provider：

```yaml
feeds:
  primary:
    url: "https://subscription.example.com/token"
```

支持 Clash、Mihomo、节点 URI、base64 和 WutherCore 原生订阅。订阅 URL 属于敏感
凭据，不要提交到仓库。官方配置给节点统一增加 `[订阅] ` 前缀，策略组的地区偏好在
重命名后执行。

如果订阅首次拉取失败，`DIRECT-FALLBACK` 仍能让内核保持可用，但此时流量是直连，
不具备代理提供的出口位置或隐私属性。面板和日志会显示当前选择，不能把直连兜底
误认为代理成功。

## 策略组

| 组名 | 策略 | 用途 |
| --- | --- | --- |
| `proxy` | manual | 面板或 API 手动选择 |
| `auto` | smart | 综合延迟、成功率、稳定性和站点记忆 |
| `low-latency` | fast | 健康检查后选择低延迟节点 |
| `failover` | stable | 按候选顺序选择首个可用节点 |
| `load-balance` | spread | 按会话分散连接 |
| `ai` | smart | AI 服务地区偏好 |
| `streaming` | smart | 流媒体地区偏好 |
| `gaming` | fast | 游戏低延迟选择 |
| `development` | stable | GitHub、开发站点和 SSH |
| `messaging` | stable | Telegram 等消息服务 |

项目当前会拒绝 `chain`，不会把未实现的多跳组降级为单跳。因此官方配置覆盖全部可
执行策略，但不写不可执行的示例。

## 规则集

远程 MRS 来自
[MetaCubeX meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)，配置使用
`meta` 分支的原始文件，并为每个集合设置独立缓存路径和刷新周期。

规则顺序是安全边界：

1. 用户例外、私有域名和私有地址先直连。
2. 广告集合随后阻断。
3. 中国大陆服务和地址直连。
4. AI、流媒体、消息、开发和游戏进入专用组。
5. 其它非中国大陆域名进入 `auto`。
6. 最终规则进入 `auto`。

MRS 文件下载失败时不会用空集合替换上次成功缓存。首次运行尚无缓存时，未加载集合
不会伪造命中，最终规则仍会处理流量。

下载的规则数据适用上游项目自己的许可证。WutherCore 仓库只保存 URL 和配置，不把
上游规则正文复制进源码。

## DNS

`domestic` 组并发查询 AliDNS 和 DNSPod，`public` 组通过 `auto`、`failover` 或
Direct 访问 Cloudflare 和 Google。代理节点域名使用 `domestic` 启动解析，避免
解析代理节点时反过来依赖尚未建立的代理连接。

DNS 规则与路由规则使用同一批规则集：

```yaml
resolver:
  nameserver-policy:
    "rule-set:cn-domain": domestic
    "rule-set:ai-global": public
  rules:
    - "set:ads -> nxdomain"
    - "set:cn-domain -> direct"
    - "any -> proxy:public?strategy=adaptive"
```

Fake IP 与 `capture.resolver: hijack` 配套启用。关闭 TUN 并只使用 Mixed 代理时，
应用是否使用该 DNS 取决于系统代理和应用自身设置。

## 平台行为

| 平台 | `method: auto` 的实际入口 | 启动条件 |
| --- | --- | --- |
| Windows | Wintun TUN | 管理员权限和可用的 Wintun |
| macOS | 系统 TUN | root 或宿主授予的网络权限 |
| Linux | root 管理的 TUN | root 或有效 `CAP_NET_ADMIN` |
| Android root | `/dev/net/tun` | 整个 daemon 以 root 或有效 capability 运行 |
| Android 非 root | VpnService TUN fd | 宿主先创建 VPN，再向内核注入 fd |

Android 的 `auto` 只选择 TUN，不会在 TPROXY 和 REDIRECT 之间自动切换。需要 root
透明代理时继续使用
[Android root TPROXY](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-tproxy.yaml)
或
[Android root REDIRECT](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-redirect.yaml)。

`capture.tun.auto_redirect` 明确保持关闭，因为它只属于 Linux 的独立 TUN 快路径，
不能放进跨平台配置。

## 上线检查

```bash
wuther-core check config.yaml
wuther-core explain config.yaml
wuther-core feeds list config.yaml
wuther-core feeds refresh config.yaml --cache-dir data/feeds
wuther-core ruleset list config.yaml
wuther-core ruleset refresh config.yaml --cache-dir data/rulesets
```

确认订阅节点数、全部规则集更新时间、`auto` 当前节点和 DNS 查询结果后再把配置加入
系统服务。完整字段仍以逐字段索引和 `check` 的严格校验为准。
