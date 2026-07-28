---
title: 高级节点与协议参数
description: 节点叠加顺序、全协议专属参数、传输组合、安全约束和完整示例
---

# 高级节点与协议参数

本页说明节点如何从 URI、结构化字段和 `params` 编译成最终出站。逐字段索引只覆盖
强类型配置，本页继续覆盖协议注册器动态读取的参数。这两部分合起来才是完整节点
配置。

可直接执行静态校验的完整文件见
[VLESS、TLS 与 gRPC 示例](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/vless-grpc.yaml)。

## 节点编译顺序

结构化节点可以单独写，也可以在 `link` 上继续覆写。运行计划按固定顺序处理：

1. 解析 `link`，得到协议、地址、认证、安全和传输基础值。
2. 强制使用对象的 `name`，不使用 URI fragment 作为最终名称。
3. 校验对象 `protocol` 与 URI 协议一致。
4. 使用对象 `address` 覆盖 URI 地址。
5. 将 `params` 叠加到 URI 查询参数。
6. 叠加 `login`、`secure`、`transport` 和 `network`。
7. 校验并应用 `streamSettings`。它的 `network` 可以覆盖 `transport.kind`。
8. 交给对应协议注册器做必填项、取值和组件检查。

这个顺序适合处理第三方 URI 中不能表达的高级字段：

```yaml
nodes:
  - name: edge-vless
    link: "vless://00000000-0000-0000-0000-000000000000@edge.example.com:443?security=tls&type=grpc"
    secure:
      tls-settings:
        serverName: edge.example.com
        alpn: [h2]
        fingerprint: chrome
        pinnedPeerCertSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    transport:
      kind: grpc
      grpcSettings:
        serviceName: edge
        authority: edge.example.com
        multiMode: true
        idle_timeout: 45s
        health_check_timeout: 10s
        permit_without_stream: false
        initial_windows_size: 1048576
        max_message_size: 4194304
        queue_capacity: 64
```

### 冲突不是覆盖

以下情况直接失败，不会猜测用户意图：

- `link` 协议与对象 `protocol` 不同。
- `login.private_key` 与 `params.private-key` 同时存在且内容不同。
- `secure.reality: false` 与 `realitySettings` 同时存在。
- 关闭 TLS 后仍配置 TLS、ECH 或证书材料。
- 普通 TLS 与 REALITY 同时启用。
- ECH 与 REALITY 同时启用。
- 平铺 `sni`、`fingerprint`、`utls` 与 `tls-settings` 中同名值不同。
- `transport.xhttp` 与非 XHTTP 的 `transport.kind` 同时存在。
- `transport.grpcSettings` 与非 gRPC 的 `transport.kind` 同时存在。
- XHTTP 与 gRPC 强类型对象同时存在。

### `params` 的值类型

`params` 是协议专属值映射。字符串、布尔值和数字保持标量语义。数组和对象会编码为
JSON，再由协议注册器解析。例如 Hysteria 2 的 `quic` 和 WireGuard 的 `peers`
必须使用对象或数组：

```yaml
params:
  fastOpen: true
  alpn: h3
  quic:
    maxIdleTimeout: 30s
    keepAlivePeriod: 10s
    disablePathMTUDiscovery: false
```

`null` 不能作为协议参数。未知参数是否拒绝取决于协议注册器，生产配置不要依赖未知
参数被忽略。

## 协议与编译组件

| `protocol` | 必要组件 | 主要认证 |
| --- | --- | --- |
| `http` | `with_http` | 用户名和密码可选 |
| `socks5` | `with_socks` | 用户名和密码可选 |
| `shadowsocks` | `with_shadowsocks` | 加密方法和密码 |
| `shadowsocksr` | `with_shadowsocksr` | 加密、协议、混淆和密码 |
| `vmess` | `with_vmess` | UUID |
| `vless` | `with_vless` | UUID |
| `trojan` | `with_trojan` | 密码 |
| `naive` | `with_naive` | 用户名和密码 |
| `snell` | `with_snell` | PSK |
| `anytls` | `with_anytls` | 密码 |
| `ssh` | `with_ssh` | 密码或私钥 |
| `hysteria` | `with_hysteria` | auth |
| `hysteria2` | `with_hysteria2` | password 或 auth |
| `tuic` | `with_tuic` | UUID 和密码 |
| `wireguard` | `with_wireguard` | 私钥和 peer |
| `mieru` | `with_mieru` | 用户名和密码 |
| `sudoku` | `with_sudoku` | key 或 password |
| `trusttunnel` | `with_trusttunnel` | 用户名和密码 |
| `young` | `with_young` | 32 字节密钥 |

传输还需要独立组件：WebSocket 使用 `with_ws`，HTTP 传输使用
`with_http_transport`，gRPC 使用 `with_grpc`，XHTTP 使用 `with_xhttp`，
QUIC 或 H3 使用 `with_quic`。REALITY 与 uTLS 分别使用 `with_reality` 和
`with_utls`。

## HTTP 与 SOCKS5

两者都从 `address` 读取服务器，从 `login.user` 和 `login.password` 读取认证。
只有用户名与密码同时存在时才启用认证，只写一项不会构成有效认证。SOCKS5 的 UDP
由 `network.udp` 控制。

```yaml
nodes:
  - name: corporate-http
    protocol: http
    address: proxy.example.com:3128
    login:
      user: alice
      password: replace-me

  - name: relay-socks
    protocol: socks5
    address: 127.0.0.1:1080
    login:
      user: alice
      password: replace-me
    network:
      udp: true
      tfo: true
      ip_family: dual
```

## Shadowsocks 与 ShadowsocksR

Shadowsocks 的加密方法来自 URI 解析结果，默认是 `aes-256-gcm`。需要非默认方法时
推荐以 URI 为基础，再用结构化字段补充插件和 socket 设置：

```yaml
nodes:
  - name: ss-2022
    link: "ss://BASE64_METHOD_AND_PASSWORD@203.0.113.10:8388#ignored"
    params:
      plugin: v2ray-plugin
      plugin-opts: "mode=websocket;host=cdn.example.com;path=/ws"
      plugin-mode: tcp
      plugin-args:
        - "--loglevel=none"
    network:
      udp: true
```

Shadowsocks 插件参数：

| 参数 | 写法 |
| --- | --- |
| `plugin` | 插件名，也可写成 `name;inline-options` |
| `plugin-opts` | 插件选项字符串 |
| `plugin-mode` | `tcp`、`udp` 或 `tcp_and_udp`，也接受对应兼容别名 |
| `plugin-args` | 命令行字符串或 JSON 字符串数组 |

配置插件选项却没有 `plugin` 会失败。插件进程的安装、权限和生命周期由部署环境负责。

ShadowsocksR 的动态参数如下：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `obfs` | `plain` | 混淆插件 |
| `protocol` | `origin` | SSR 协议插件 |
| `obfs-param` | 空 | 混淆参数 |
| `protocol-param` | 空 | 协议参数 |

加密方法同样来自 URI 解析结果，默认 `aes-256-cfb`。

## VMess 与 VLESS

VMess 和 VLESS 都从 `login.uuid` 读取用户标识。VMess 额外接受：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `aid` | `0` | 大于零时启用旧版 VMess |
| `security` 或 `scy` | 实现默认值 | VMess 加密方式 |
| `tls` | 继承安全配置 | URI 兼容开关 |
| `allowInsecure` | `false` | URI 和 provider 的旧格式兼容值，会实际关闭证书校验；新配置优先使用证书固定或名称验证 |
| `alpn` | 自动 | ALPN 列表 |
| `network` 或 `net` | `tcp` | 传输类型兼容写法 |

支持的传输为 `tcp`、`ws`、`http`、`h2`、`grpc` 和 `xhttp`。结构化
`transport.kind` 比平铺参数更清楚。

### VLESS、REALITY 与 gRPC

```yaml
nodes:
  - name: vless-reality-grpc
    protocol: vless
    address: 203.0.113.20:443
    login:
      uuid: 00000000-0000-0000-0000-000000000000
    secure:
      reality: true
      realitySettings:
        fingerprint: chrome
        serverName: www.example.com
        publicKey: REPLACE_WITH_REALITY_PUBLIC_KEY
        shortId: 0123456789abcdef
        spiderX: /
    transport:
      kind: grpc
      grpcSettings:
        authority: www.example.com
        serviceName: tunnel
        multiMode: true
        idle_timeout: 45s
        health_check_timeout: 10s
        permit_without_stream: false
        initial_windows_size: 1048576
        user_agent: grpc-go/1.64
        max_message_size: 4194304
        queue_capacity: 64
    streamSettings:
      sockopt:
        tcpFastOpen: true
        tcpKeepAliveIdle: 60
        tcpKeepAliveInterval: 15
        domainStrategy: UseIP
        happyEyeballs:
          tryDelayMs: 250
          interleave: 1
          maxConcurrentTry: 4
```

`publicKey` 是旧名称，服务端使用新语义时也可以写 `password`。两者同时存在必须
解码为相同内容。`shortId`、`serverName`、fingerprint 和服务端必须一致。

### VLESS、TLS 与 WebSocket

```yaml
nodes:
  - name: vless-ws
    protocol: vless
    address: edge.example.com:443
    login:
      uuid: 00000000-0000-0000-0000-000000000000
    secure:
      tls: true
      tls-settings:
        serverName: edge.example.com
        alpn: [http/1.1]
        fingerprint: chrome
    transport:
      kind: ws
      host: edge.example.com
      path: /assets
```

WebSocket 读取 `host` 和 `path`。HTTP 传输的 path 与 host 支持逗号分隔列表，
方法用 `http-method`。H2 传输对应 `h2-host`、`path` 和 `h2-method`。

## Trojan

Trojan 的密码来自 `login.password`，TLS 默认启用。只有明确写
`params.security: none` 或 `params.tls: false` 才关闭 TLS。常用参数为
`allowInsecure` 和 `alpn`，UDP 由 `network.udp` 控制。

```yaml
nodes:
  - name: trojan-xhttp
    protocol: trojan
    address: edge.example.com:443
    login:
      password: replace-me
    secure:
      tls: true
      tls-settings:
        serverName: edge.example.com
        alpn: [h2]
    transport:
      kind: xhttp
      xhttp:
        host: edge.example.com
        path: /api
        mode: packet-up
        xPaddingBytes: 100-1000
        xmux:
          maxConcurrency: 8-16
    network:
      udp: true
```

Trojan 当前只对 gRPC 与 XHTTP 使用专属传输构造。更复杂的 XHTTP 组合见
[高级 XHTTP、StreamSettings 与 FinalMask](advanced-xhttp-finalmask.md)。

## Naive

Naive 使用 `login.user`、`login.password` 和 `secure.sni`。主要动态参数：

| 参数 | 说明 |
| --- | --- |
| `insecure-concurrency` | H2 并发连接数，最小为 1 |
| `udp-over-tcp` | `network.udp` 启用后使用 UoT v2 |
| `quic` | 启用 HTTP/3 |
| `quic-congestion-control` | `bbr`、`bbr2`、`cubic` 或 `reno` |
| `stream-receive-window` | QUIC 单流接收窗口 |
| `quic-session-receive-window` | QUIC 会话接收窗口 |
| `extra-header.NAME` | 单个自定义请求头 |
| `certificate-path` | PEM 根证书路径 |
| `certificate` | 内联 PEM 根证书 |
| `ech` | 启用 ECH |
| `ech-config` | 十六进制、Base64 或 PEM 内容中的 ECHConfigList |
| `ech-query-server-name` | 查询 ECH HTTPS 记录时使用的名称 |

```yaml
nodes:
  - name: naive-h3
    protocol: naive
    address: proxy.example.com:443
    login:
      user: alice
      password: replace-me
    secure:
      sni: proxy.example.com
    network:
      udp: true
    params:
      quic: true
      udp-over-tcp: true
      quic-congestion-control: bbr
      stream-receive-window: 8388608
      quic-session-receive-window: 16777216
      extra-header.X-Client: WutherCore
      ech: true
      ech-query-server-name: proxy.example.com
```

`insecure` 和跳过证书验证参数会被拒绝。私有 CA 必须通过
`certificate-path` 或 `certificate` 注入。完整部署依赖见 [Naive](../NAIVE.md)。

## Snell

Snell 从 `login.password` 或 `params.psk` 读取 PSK。

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `params.cipher` 或 URI method | `aes-128-gcm` | `aes-128-gcm` 或 `chacha20-poly1305` |
| `version` | 实现默认值 | Snell 协议版本 |
| `obfs` | 无 | `http` 或 `tls` |
| `obfs-host` | 空 | 混淆 Host |

```yaml
nodes:
  - name: snell-edge
    protocol: snell
    address: edge.example.com:443
    login:
      password: replace-me
    params:
      version: 5
      cipher: chacha20-poly1305
      obfs: tls
      obfs-host: www.example.com
```

## AnyTLS

AnyTLS 密码必填。高级参数：

| 参数 | 说明 |
| --- | --- |
| `clientId` | 可选客户端标识 |
| `disable-sni` | 不发送 SNI |
| `insecure` | 跳过证书验证 |
| `alpn` | ALPN 列表 |
| `fingerprint` 或 `fp` | TLS 指纹 |
| `enableSessionResumption` | TLS 会话恢复 |
| `idleSessionCheckInterval` | 空闲会话扫描间隔 |
| `idleSessionTimeout` | 空闲会话超时 |
| `minIdleSession` | 预热空闲会话数 |
| `disableReuse` | 禁止会话复用 |
| `udp-over-tcp` | UoT 开关，默认继承 `network.udp` |

```yaml
nodes:
  - name: anytls-edge
    protocol: anytls
    address: edge.example.com:443
    login:
      password: replace-me
    secure:
      sni: edge.example.com
    params:
      clientId: laptop
      alpn: "h2,http/1.1"
      fingerprint: chrome
      enableSessionResumption: true
      idleSessionCheckInterval: 30s
      idleSessionTimeout: 60s
      minIdleSession: 2
      disableReuse: false
      udp-over-tcp: true
    network:
      udp: true
```

协议背景与完整行为见 [AnyTLS](../ANYTLS.md)。

## SSH

SSH 的 `login.user` 必填。可以只用密码、只用私钥，或先尝试公钥再使用密码。

| 参数 | 说明 |
| --- | --- |
| `private-key` | 内联 PEM 私钥或私钥文件路径 |
| `private-key-passphrase` | 加密私钥口令 |
| `host-key` 或 `known-hosts` | 每行一条可信主机公钥 |
| `host-key-algorithms` | 逗号或换行分隔的算法列表 |
| `client-version` | SSH 客户端版本字符串 |
| `keepalive-interval` | 秒数 |

```yaml
nodes:
  - name: ssh-bastion
    protocol: ssh
    address: bastion.example.com:22
    login:
      user: deploy
      private_key: /etc/wuther/keys/deploy_ed25519
    params:
      private-key-passphrase: replace-me
      known-hosts: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIREPLACE"
      host-key-algorithms: "ssh-ed25519,rsa-sha2-512"
      client-version: SSH-2.0-WutherCore
      keepalive-interval: 30
```

`login.private_key` 与 `params.private-key` 是同一语义，值不同会失败。生产环境不要
省略 host key 校验。

## Hysteria 1

Hysteria 1 必须使用 UDP。`up` 和 `down` 必填，可写整数 Mbps，也可使用精确速率
单位。主要参数：

| 参数 | 说明 |
| --- | --- |
| `auth`、`auth-str`、`password` 或 `user` | 认证字符串 |
| `up`、`down` | 上下行带宽 |
| `fastOpen` | 快速打开 |
| `insecure` | 跳过证书验证 |
| `alpn` | 默认 `hysteria` |
| `handshake-timeout` | 握手超时，不能小于 2 秒 |
| `obfs` 或 `obfs-password` | 混淆密码 |

`lazy: false` 会被拒绝，不能用它表达默认值。其它行为见
[Hysteria 1 与 2](../HYSTERIA.md)。

## Hysteria 2

Hysteria 2 支持平铺参数，也支持官方风格结构化对象。结构化写法适合完整配置：

同一配置也保存在
[Hysteria 2 结构化示例](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/hysteria2-structured.yaml)。

```yaml
nodes:
  - name: hy2-advanced
    protocol: hysteria2
    address: edge.example.com:443
    login:
      password: replace-me
    network:
      udp: true
    params:
      bandwidth:
        up: 100 mbps
        down: 500 mbps
        disableLossCompensation: false
      congestion:
        type: bbr
        bbrProfile: standard
      obfs:
        type: gecko
        gecko:
          password: replace-obfs-password
          minPacketSize: 512
          maxPacketSize: 1200
      quic:
        initStreamReceiveWindow: 8388608
        maxStreamReceiveWindow: 16777216
        initConnReceiveWindow: 16777216
        maxConnReceiveWindow: 33554432
        maxIdleTimeout: 30s
        keepAlivePeriod: 10s
        disablePathMTUDiscovery: false
        sockopts:
          bindInterface: eth0
          fwmark: 255
      tls:
        sni: edge.example.com
        insecure: false
        pinSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      transport:
        type: udp
        udp:
          minHopInterval: 20s
          maxHopInterval: 40s
```

结构化对象约束：

- `obfs.type` 支持 `none`、`plain`、`salamander` 和 `gecko`。
- `salamander` 与 `gecko` 都需要同名嵌套对象和密码。Gecko 默认包长范围为
  512 到 1200。
- `quic.sockopts` 支持 `bindInterface` 与 `fwmark`。
- `fdControlUnixSocket` 当前明确不支持。
- TLS 客户端证书和私钥必须同时配置。
- 固定 hop interval 与最小加最大区间互斥。
- Hysteria 2 始终使用 TLS。
- `lazy: false` 同样会被拒绝。

## TUIC

TUIC 的 UUID 和密码都必填。常用参数：

| 参数 | 说明 |
| --- | --- |
| `udp-relay-mode` | `native` 或 `quic` |
| `alpn` | ALPN 列表 |
| `insecure` | 跳过证书验证 |
| `disable-sni` | 不发送 SNI |
| `heartbeat-interval` | 毫秒整数 |
| `heartbeat` | 时长，例如 `10s` |

```yaml
nodes:
  - name: tuic-edge
    protocol: tuic
    address: edge.example.com:443
    login:
      uuid: 00000000-0000-0000-0000-000000000000
      password: replace-me
    secure:
      sni: edge.example.com
    params:
      udp-relay-mode: native
      alpn: h3
      heartbeat: 10s
    network:
      udp: true
```

## WireGuard

WireGuard 使用结构化 `params.peers`、私钥、地址、MTU 和路由字段。它还涉及多 peer
选择、allowed IP、保留位、系统接口和 DNS 等组合。完整配置与约束集中在
[WireGuard](../WIREGUARD.md)，不要把 peer 数组压成字符串。

## Mieru、Sudoku、TrustTunnel 与 Young

### Mieru

Mieru 使用 `login.user` 和 `login.password`。`params.cipher` 选择加密方式。

```yaml
nodes:
  - name: mieru-edge
    protocol: mieru
    address: edge.example.com:443
    login:
      user: alice
      password: replace-me
    params:
      cipher: AES-256-GCM
```

### Sudoku

Sudoku 需要 `key` 或 `password`。高级参数：

| 参数 | 说明 |
| --- | --- |
| `aead-method` 或 `method` | AEAD 算法 |
| `table-type` | 表类型 |
| `custom-table` | 自定义表 |
| `padding-min`、`padding-max` | 填充范围 |
| `disable-http-mask` | 关闭 HTTP mask |
| `path-root` | 路径根 |

### TrustTunnel

TrustTunnel 使用用户名和密码，TLS 名称来自 `secure.sni`。

| 参数 | 说明 |
| --- | --- |
| `skip-cert-verify` 或 `insecure` | 跳过证书验证 |
| `alpn` | ALPN 列表 |
| `max-connections` | 最大连接数 |
| `min-streams`、`max-streams` | 每连接流数量 |
| `health-check` | 健康检查设置 |

### Young

Young 的 key 从 `login.user` 或 `login.password` 读取，必须解码为 32 字节。证书
固定使用 `pin-sha256`、`pin_sha256` 或 `pin`，接受 64 位十六进制或 Base64URL。

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `sni` | 服务器名 | TLS Server Name |
| `authority` | 服务器名 | HTTP authority |
| `padding-min` | `64` | 最小填充 |
| `padding-max` | `512` | 最大填充 |
| `path` | `/assets` | 请求路径 |
| `idle-secs` | `300` | 空闲超时 |
| `max-streams` | `1024` | 最大并发流 |

更多协议背景见 [Young](../YOUNG_PROTOCOL.md)。

## 出站拨号链

`streamSettings.sockopt.dialerProxy` 可以让一个节点通过另一个节点拨号：

```yaml
nodes:
  - name: first-hop
    protocol: socks5
    address: 127.0.0.1:1080

  - name: exit-vless
    protocol: vless
    address: edge.example.com:443
    login:
      uuid: 00000000-0000-0000-0000-000000000000
    secure:
      tls: true
      sni: edge.example.com
    streamSettings:
      sockopt:
        dialerProxy: first-hop
```

被引用节点必须存在。直接或间接形成循环都会在运行计划编译时失败。DNS 出站通过
多出口服务实现，不应使用拨号链替代 DNS 的 `exits`。

## 组件最小化

组件标签应从实际配置反推。上面的 VLESS、REALITY、gRPC 示例至少需要：

```text
with_vless,with_reality,with_grpc,with_utls
```

Hysteria 2 结构化示例至少需要：

```text
with_hysteria2,with_quic
```

启用一个协议组件不会自动包含所有传输组件。构建方法、标签别名和 CI 矩阵见
[组件化构建](../BUILDING.md)。

## 上线前检查

```bash
wuther-core components
wuther-core check config.yaml
wuther-core explain config.yaml
```

检查结果应同时满足：

- 所有协议和传输组件都存在。
- `explain` 中最终协议、地址、TLS、传输和 socket 设置符合预期。
- 没有依赖重复节点名自动追加的 `-2`、`-3` 后缀。
- 私钥、密码、固定证书和订阅解密密钥没有进入公开日志。
- 健康检查验证的是最终拨号链，不只是第一跳可达。
