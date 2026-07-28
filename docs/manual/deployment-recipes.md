---
title: 完整部署方案
description: Windows、macOS、Linux、路由器、Android 和服务端的完整配置与最小构建
---

# 完整部署方案

本页给出按平台拆分的生产模板。每份模板都说明宿主边界、最小组件和验证方法。
示例中的域名、UUID、密码、证书和订阅地址必须替换。

仓库还提供可直接运行 `check` 的
[XHTTP 服务端完整示例](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/xhttp-server.yaml)。

## 选择方案

| 环境 | 推荐入口 | 系统接管 |
| --- | --- | --- |
| Windows 桌面 | 本地 Mixed 代理 | 先用系统代理，TUN 依赖宿主集成 |
| macOS 桌面 | 本地 Mixed 代理 | 先用系统代理，TUN 依赖授权与宿主集成 |
| Linux 桌面 | Mixed 或 TUN | 可由进程管理 TUN |
| Linux 路由器 | TUN `auto_redirect` | 需要 root、nftables 和策略路由 |
| Android root | root TUN、TPROXY 或 REDIRECT | daemon 必须真正持有 root 或有效 `CAP_NET_ADMIN` |
| Android 非 root | VpnService 提供 TUN fd | 宿主必须配置 Builder 并 protect 出站 |
| 服务端 | XHTTP、gRPC、REALITY 或协议入站 | 不启用客户端 capture |

## Windows 桌面

### 配置

```yaml
version: 1
profile: desktop
name: windows-desktop

log:
  on: true
  level: info
  stdout: true
  format: text

listen:
  local:
    host: 127.0.0.1
    port: 7890
    udp: true
  panel: 127.0.0.1:9090
  share: false

feeds:
  primary:
    url: https://subscription.example.com/token
    every: 6h
    via: direct
    keep:
      name_has: [香港, 日本, 新加坡, 美国]
    drop:
      name_has: [过期, 剩余, 官网]
    rename:
      add_prefix: "[A] "

nodes:
  - name: emergency
    protocol: socks5
    address: 127.0.0.1:1080
    network:
      udp: true

groups:
  main:
    choose: smart
    use: [primary, nodes]
    prefer: [香港, 日本, 新加坡]
    avoid: [过期, emergency]
    check: https://www.gstatic.com/generate_204
    sticky: site

  manual:
    choose: manual
    use: [primary, nodes]

route:
  preset: cn_smart
  steps:
    - "process:wuther-core -> direct"
    - "ip:127.0.0.0/8 -> direct"
    - "ip:192.168.0.0/16 -> direct"
    - "ads -> block"
    - "github -> main"
  final: main

resolver:
  mode: smart
  fake: off
  servers:
    domestic: https://223.5.5.5/dns-query
    public:
      endpoint: https://1.1.1.1/dns-query
      exits: [main, DIRECT]
      strategy: adaptive
      timeout: 3s
  nameserver: [domestic]
  fallback: [public]
  proxy-server-nameserver: [domestic]
  direct-nameserver: [domestic]

capture:
  on: false

smart:
  on: true
  goal: balanced
  learn: 14d
  sticky: site
  explain: true

ui:
  on: true
  secret: REPLACE_WITH_RANDOM_TOKEN
  dashboard: auto
  api:
    native: true
    clash_compat: true
```

让浏览器或系统代理指向 `127.0.0.1:7890`。这条路径不依赖网卡驱动，最适合作为
Windows 首次部署和故障恢复入口。

### 最小构建

上面配置的手动兜底只需要 SOCKS，订阅中的协议仍决定其它组件。订阅协议不固定时用
`standard`：

```powershell
.\build.cmd --tags "standard" windows
```

只允许 VLESS、REALITY 和 gRPC 时：

```powershell
.\build.cmd --tags "with_api,with_socks,with_vless,with_reality,with_grpc,with_utls" windows
```

Windows ARM64 使用：

```powershell
.\build.cmd --tags "standard" win-arm64
```

不要在 Windows 配置 Linux 专属的 mark、MPTCP、拥塞控制和 TCP window 字段。

## macOS 桌面

### 配置

macOS 本地代理配置与 Windows 类似，但接口绑定和系统代理应由启动器管理：

```yaml
version: 1
profile: desktop
name: macos-desktop

listen:
  local:
    host: 127.0.0.1
    port: 7890
    udp: true
  panel: 127.0.0.1:9090
  share: false

feeds:
  primary:
    url: https://subscription.example.com/token
    every: 6h
    via: direct

groups:
  main:
    choose: stable
    use: [primary]
    prefer: [香港, 日本, 新加坡]
    check: https://www.gstatic.com/generate_204
    sticky: site

route:
  preset: cn_smart
  steps:
    - "ip:127.0.0.0/8 -> direct"
    - "ip:192.168.0.0/16 -> direct"
    - "ads -> block"
  final: main

resolver:
  mode: smart
  fake: off
  servers:
    bootstrap: https://223.5.5.5/dns-query
    secure:
      endpoint: https://1.1.1.1/dns-query
      exits: [main, DIRECT]
      strategy: adaptive
      timeout: 3s
  nameserver: [secure]
  proxy-server-nameserver: [bootstrap]
  direct-nameserver: [bootstrap]

capture:
  on: false

smart:
  on: true
  goal: stability
  learn: 14d
  sticky: site
  explain: true

ui:
  on: true
  secret: REPLACE_WITH_RANDOM_TOKEN
```

宿主应在启动成功后设置 macOS 网络服务的 HTTP、HTTPS 和 SOCKS 代理，退出时恢复
原值。不要让崩溃后的残留系统代理指向不存在的进程。

### 原生构建

Apple Silicon：

```bash
rustup target add aarch64-apple-darwin
cargo build --release -p wuther-core \
  --target aarch64-apple-darwin \
  --no-default-features \
  --features "standard"
```

Intel：

```bash
rustup target add x86_64-apple-darwin
cargo build --release -p wuther-core \
  --target x86_64-apple-darwin \
  --no-default-features \
  --features "standard"
```

在 macOS 上也可直接调用 PowerShell 脚本：

```bash
pwsh -File scripts/build-all.ps1 \
  -Tags "standard" \
  -Targets "aarch64-apple-darwin"
```

仓库 CI 仅对 Apple Silicon 使用原生 runner，不依赖缺少 Apple SDK 的普通交叉编译
环境。Intel 命令保留给自行维护该架构的构建者，官方 CI 和 Release 不再产出 Intel
macOS 二进制。

### TUN 边界

配置模型支持：

```yaml
capture:
  on: true
  method: virtual_nic
  traffic: system
  resolver: hijack
  stack: mixed
  tun:
    interface_name: wuthertun0
    address:
      - 172.19.0.1/30
      - fdfe:dcba:9876::1/126
    auto_route: true
    strict_route: false
    route_exclude_address:
      - 127.0.0.0/8
      - ::1/128
      - 192.168.0.0/16
```

但设备授权、签名、路由安装和系统扩展生命周期属于 macOS 宿主。没有实现这些宿主
步骤时，保留 `capture.on: false`。

## Linux 桌面

### 配置

```yaml
version: 1
profile: desktop
name: linux-tun

listen:
  local: 7890
  panel: 127.0.0.1:9090
  share: false

feeds:
  primary:
    url: https://subscription.example.com/token
    every: 6h
    via: direct

groups:
  main:
    choose: smart
    use: [primary]
    prefer: [香港, 日本, 新加坡]
    check: https://www.gstatic.com/generate_204
    sticky: site

route:
  preset: cn_smart
  steps:
    - "process:wuther-core -> direct"
    - "ip:10.0.0.0/8 -> direct"
    - "ip:172.16.0.0/12 -> direct"
    - "ip:192.168.0.0/16 -> direct"
    - "ads -> block"
  final: main

resolver:
  mode: smart
  fake: auto
  servers:
    bootstrap: https://223.5.5.5/dns-query
    public:
      endpoint: https://1.1.1.1/dns-query
      exits: [main, DIRECT]
      strategy: adaptive
      timeout: 3s
  nameserver: [public]
  proxy-server-nameserver: [bootstrap]
  direct-nameserver: [bootstrap]

capture:
  on: true
  method: virtual_nic
  traffic: system
  resolver: hijack
  stack: mixed
  mtu: 1400
  offload: true
  exclude:
    process: [wuther-core]
    cidr: [127.0.0.0/8, ::1/128]
  tun:
    interface_name: rpktun0
    address:
      - 172.19.0.1/30
      - fdfe:dcba:9876::1/126
    auto_route: true
    strict_route: false
    route_exclude_address:
      - 127.0.0.0/8
      - ::1/128
      - 192.168.0.0/16
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 223.5.5.5/32
      - 1.1.1.1/32
    endpoint_independent_nat: true
    udp_timeout: 5m

smart:
  on: true
  goal: balanced
  learn: 14d
  sticky: site

ui:
  on: true
  secret: REPLACE_WITH_RANDOM_TOKEN
```

### 构建与权限

```bash
cargo build --release -p wuther-core \
  --no-default-features \
  --features "standard"

sudo setcap cap_net_admin,cap_net_raw+ep target/release/wuther-core
target/release/wuther-core check config.yaml
target/release/wuther-core run --config config.yaml
```

使用 systemd 时应把配置、缓存、日志和持久化状态放在明确目录，并使用受限服务用户。
是否使用 capability 或 root 由网络管理方式决定。

## Linux 路由器

### 配置

```yaml
version: 1
profile: router
name: linux-gateway

listen:
  local:
    host: 0.0.0.0
    port: 7890
    udp: true
  panel: 0.0.0.0:9090
  share: home

feeds:
  primary:
    url: https://subscription.example.com/token
    every: 6h
    via: direct

groups:
  main:
    choose: stable
    use: [primary]
    prefer: [香港, 日本, 新加坡]
    check: https://www.gstatic.com/generate_204
    sticky: site

route:
  preset: cn_smart
  steps:
    - "ip:10.0.0.0/8 -> direct"
    - "ip:172.16.0.0/12 -> direct"
    - "ip:192.168.0.0/16 -> direct"
    - "ip:100.64.0.0/10 -> direct"
    - "ads -> block"
  final: main

resolver:
  mode: smart
  fake: auto
  listen: 0.0.0.0:1053
  servers:
    bootstrap: https://223.5.5.5/dns-query
    public:
      endpoint: https://1.1.1.1/dns-query
      exits: [main, DIRECT]
      strategy: adaptive
      timeout: 3s
      max-parallel: 2
  nameserver: [public]
  proxy-server-nameserver: [bootstrap]
  direct-nameserver: [bootstrap]

capture:
  on: true
  method: virtual_nic
  traffic: system
  resolver: hijack
  stack: mixed
  mtu: 1400
  tun:
    interface_name: rpktun0
    address:
      - 172.19.0.1/30
      - fdfe:dcba:9876::1/126
    auto_route: true
    auto_redirect: true
    strict_route: false
    iproute2_table_index: 2024
    iproute2_rule_index: 9100
    route_exclude_address:
      - 127.0.0.0/8
      - ::1/128
      - 192.168.0.0/16
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 100.64.0.0/10
      - 223.5.5.5/32
      - 1.1.1.1/32
    endpoint_independent_nat: true
    udp_timeout: 5m

ui:
  on: true
  secret: REPLACE_WITH_LONG_RANDOM_TOKEN
  cors: []
```

`auto_redirect` 当前只接受 Linux、root managed TUN、`virtual_nic`、
`traffic: system`、`auto_route: true` 和 `strict_route: false` 的安全组合。
路由表所有权、nftables 原子安装和回滚契约见
[Linux TUN auto_redirect](../LINUX-TUN-AUTO-REDIRECT.md)。

路由器最小构建至少需要 `with_tun` 加实际订阅协议。协议不可控时：

```bash
cargo build --release -p wuther-core \
  --no-default-features \
  --features "standard"
```

公开面板监听必须配置强 secret，并由防火墙限制管理网段。

## Android

Android 不是只有 VpnService。native 核心提供三种 root 数据面和一种非 root 数据面：

| 模式 | 配置 | 能力 |
| --- | --- | --- |
| root TUN | `method: virtual_nic` | TCP、UDP、DNS 劫持、UID、GID、Android user 和包名过滤 |
| root TPROXY | `method: tproxy` | 双栈 TCP 和 UDP 透明代理 |
| root REDIRECT | `method: redirect` | 双栈 TCP NAT REDIRECT，UDP 不接管 |
| VpnService | `method: virtual_nic` | 宿主创建 TUN fd，native 负责数据面 |

完整权限模型、源码调用链、过滤器边界、Magisk 与 KernelSU 启动方式见
[Android 完整部署](android.md)。

### root TUN

```yaml
capture:
  on: true
  method: virtual_nic
  traffic: system
  resolver: hijack
  stack: mixed
  mtu: 1400
  tun:
    interface_name: rpktun0
    address:
      - 172.19.0.1/30
      - fdfe:dcba:9876::1/126
    inet6: true
    auto_route: true
    auto_redirect: false
    strict_route: false
    include_android_user: [0]
    exclude_package:
      - com.android.captiveportallogin
```

native 会优先打开 `/dev/net/tun`，成功后自行管理接口、路由和出站 fwmark。
完整配置见
[`android-root-tun.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-tun.yaml)。

### root TPROXY

```yaml
capture:
  on: true
  method: tproxy
  traffic: system
  resolver: hijack
  stack: mixed
  exclude:
    cidr:
      - 127.0.0.0/8
      - ::1/128
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
  tun:
    inet6: true
    auto_redirect: false
    auto_redirect_output_mark: "0x2024"
```

这条路径使用固定端口 `7894`，固定 TPROXY mark 和路由表 `0x2d0`，同时处理 TCP
和 UDP。它要求当前 daemon 具有有效 `CAP_NET_ADMIN`，并能调用 iptables 和
ip6tables。完整配置见
[`android-root-tproxy.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-tproxy.yaml)。

### root REDIRECT

```yaml
capture:
  on: true
  method: redirect
  traffic: system
  resolver: off
  stack: system
  exclude:
    cidr:
      - 127.0.0.0/8
      - ::1/128
  tun:
    inet6: true
    auto_redirect: false
    include_android_user: [0]
    exclude_uid: [1000]
```

REDIRECT 使用 nftables 原子发布 TCP NAT 规则。它不接管 UDP，也不能直接消费包名
过滤，包名需要先转换成 UID。完整配置见
[`android-root-redirect.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-redirect.yaml)。

### root 启动要求

内核启动时的 `su -c id` 只做探测，不会改变当前进程身份。root 模式必须由 root
shell、Magisk service 或 KernelSU service 启动整个 daemon，或者让 daemon
真正持有有效 capability。

```bash
adb shell su -c '/data/local/tmp/wuther-core check /data/local/tmp/config.yaml'
adb shell su -c '/data/local/tmp/wuther-core run --config /data/local/tmp/config.yaml'
```

### VpnService

Android 的 native 核心不负责调用 `VpnService.Builder.establish()`。宿主必须：

1. 从配置获取地址、路由、DNS、应用包含和排除列表。
2. 把这些值写入 `VpnService.Builder`。
3. 调用 `establish()` 得到 TUN fd。
4. 把 fd 交给 native 核心。
5. 让所有代理出站 socket 调用 `VpnService.protect(fd)`。

#### 配置

```yaml
version: 1
profile: mobile
name: android-vpn

listen:
  local:
    host: 127.0.0.1
    port: 7890
    udp: true
  panel: 127.0.0.1:9090
  share: false

feeds:
  primary:
    url: https://subscription.example.com/token
    every: 6h
    via: direct

groups:
  main:
    choose: smart
    use: [primary]
    prefer: [香港, 日本, 新加坡]
    check: https://www.gstatic.com/generate_204
    sticky: site

route:
  preset: cn_smart
  steps:
    - "ip:10.0.0.0/8 -> direct"
    - "ip:172.16.0.0/12 -> direct"
    - "ip:192.168.0.0/16 -> direct"
    - "ads -> block"
  final: main

resolver:
  mode: smart
  fake: auto
  servers:
    bootstrap: https://223.5.5.5/dns-query
    public:
      endpoint: https://1.1.1.1/dns-query
      exits: [main, DIRECT]
      strategy: adaptive
      timeout: 3s
  nameserver: [public]
  proxy-server-nameserver: [bootstrap]
  direct-nameserver: [bootstrap]

capture:
  on: true
  method: virtual_nic
  traffic: system
  resolver: hijack
  stack: mixed
  mtu: 1400
  tun:
    interface_name: rpktun0
    address:
      - 172.19.0.1/30
      - fdfe:dcba:9876::1/126
    auto_route: true
    auto_redirect: false
    strict_route: false
    route_exclude_address:
      - 127.0.0.0/8
      - ::1/128
      - 192.168.0.0/16
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 223.5.5.5/32
      - 1.1.1.1/32
    endpoint_independent_nat: true
    udp_timeout: 5m
    include_android_user: [0]
    exclude_package:
      - com.android.captiveportallogin
    platform:
      http_proxy:
        enabled: true
        server: 127.0.0.1
        server_port: 7890
        bypass_domain: [localhost, "*.lan", "*.local"]

smart:
  on: true
  goal: balanced
  learn: 14d
  sticky: site

ui:
  on: true
  secret: REPLACE_WITH_RANDOM_TOKEN
```

不要在 Android 打开 `tun.auto_redirect`。它是 Linux root TUN 的混合数据面，
不是 Android root 模式开关。Android root 使用显式 `method: virtual_nic`、
`method: tproxy` 或 `method: redirect`。

VpnService 的应用筛选由 Builder 与 native 数据面共同实现，宿主不能只把字段交给
内核就假定系统已经执行。

### Android 构建

```powershell
pwsh -File scripts/build-all.ps1 `
  -Tags "standard" `
  -Targets "aarch64-linux-android"
```

精简到 VLESS、REALITY、gRPC、API 和 TUN：

```powershell
pwsh -File scripts/build-all.ps1 `
  -Tags "with_api,with_tun,with_vless,with_reality,with_grpc,with_utls" `
  -Targets "aarch64-linux-android"
```

推荐 Android NDK r26 或更新版本，并设置 `ANDROID_NDK_HOME`。三种 root 数据面和
VpnService 都要求编译 `with_tun`。完整宿主调用顺序和更多包过滤示例见
[Android 完整部署](android.md)。

## XHTTP 服务端

### 配置

```yaml
version: 1
profile: server
name: xhttp-server

log:
  on: true
  level: info
  stdout: true
  format: json

listen:
  panel: 127.0.0.1:9090
  share: false
  xhttp:
    address: 0.0.0.0
    port: 443
    allow-unauthenticated-non-loopback: true
    alpn: [h2, http/1.1]
    tls:
      certificates:
        - certificateFile: /etc/wuther/tls/fullchain.pem
          keyFile: /etc/wuther/tls/private.key
          usage: encipherment
          ocspStapling: 3600
      minVersion: "1.2"
      maxVersion: "1.3"
      rejectUnknownSni: true
    target:
      host: 127.0.0.1
      port: 10000
    max-active-connections: 4096
    max-concurrent-streams: 128
    max-active-http-streams: 4096
    http-idle-timeout: 90s
    settings:
      host: edge.example.com
      path: /api
      mode: auto
      xPaddingBytes: 100-1000
      xmux:
        maxConcurrency: 8-16

route:
  preset: direct
  final: direct

resolver:
  mode: secure
  fake: off
  servers:
    primary: https://1.1.1.1/dns-query
  nameserver: [primary]

capture:
  on: false

ui:
  on: true
  secret: REPLACE_WITH_LONG_RANDOM_TOKEN
```

`target` 应指向本机受认证的 VLESS、Trojan 或其它服务。Raw XHTTP 适配层本身没有
协议级认证，因此非回环绑定必须显式设置
`allow-unauthenticated-non-loopback: true`。这个确认不增加认证能力，公网部署必须
让 target 协议完成认证，并用防火墙限制暴露面。H3 必须放在独立的 XHTTP 监听项中，
并且该项 `alpn` 只能是 `h3`，不能与 H1 或 H2 混写。服务端组件：

```bash
cargo build --release -p wuther-core \
  --no-default-features \
  --features "with_api,with_xhttp,with_quic"
```

如果 target 协议由同一进程提供，还要加入对应协议组件。`with_xhttp` 自动包含
`with_quic`，显式写出便于审查构建意图。

### 服务管理

服务端部署至少应做到：

- 配置文件只对服务用户可读。
- 证书私钥与配置分开授权。
- API 只监听回环或受控管理网，并设置 secret。
- systemd 使用独立用户、明确工作目录和写目录。
- 防火墙只开放必要的数据端口。
- 发布前记录 `wuther-core components --json`。
- 更新前运行新二进制的 `check`，再做可回滚切换。

## 配置和组件一致性

每个平台最终都执行同一组检查：

```bash
wuther-core components
wuther-core components --json
wuther-core check config.yaml
wuther-core explain config.yaml
```

精简构建最容易漏掉订阅后续新增的协议。生产上有两种可靠做法：

1. 订阅协议不可控时使用 `standard`。
2. 固定允许协议时使用精确标签，并在订阅刷新后监控被拒绝协议。

归档中的 `BUILD-COMPONENTS.txt`、运行时 `components` 和配置实际使用组件应保持
一致。完整标签表和 CI 输入见 [组件化构建](../BUILDING.md)。
