---
title: 监听与入站
description: Mixed、Panel 和所有服务端协议入站的配置语义
---

# 监听与入站

`listen` 同时管理本地代理入口、管理面板和可选服务端协议。每个服务端协议都有独立
监听地址和资源限制。二进制必须包含对应组件，否则 `run` 会拒绝启动。

完整字段、别名和枚举见[监听与入站字段索引](generated/inbounds.md)。

## `listen` 字段

| 字段 | 形态 | 用途 |
| --- | --- | --- |
| `local` | 端口或对象 | Mixed HTTP、SOCKS5 和 UDP 本地入口 |
| `panel` | 端口或地址 | 原生 API 与 Clash 兼容 API 的监听地址 |
| `xhttp` | 对象或对象列表 | XHTTP 和 SplitHTTP 服务端入站 |
| `shadowsocks` | 对象或对象列表 | Shadowsocks SIP003、SIP004 和 SIP022 服务端 |
| `share` | 布尔值、`home` 或 `all` | 控制 Profile 生成的本地监听是否对外共享 |
| `auth` | 字符串列表 | `user:password` 形式的全局 Mixed 认证 |
| `reality` | 对象列表 | REALITY 安全层和内层协议 |
| `wireguard` | 对象列表 | WireGuard UDP 服务端 |
| `young` | 对象列表 | Young Neqo HTTP/3 和 WebTransport 服务端 |
| `grpc` | 对象列表 | Xray gRPC 服务端 |

## Mixed 本地入口

端口短写：

```yaml
listen:
  local: 7890
```

对象长写：

```yaml
listen:
  local:
    host: 127.0.0.1
    port: 7890
    udp: true
    auth:
      - "alice:replace-me"
```

`host` 默认 `127.0.0.1`，`udp` 默认开启。对象内 `auth` 只应用于这个监听；
顶层 `listen.auth` 是 Profile 和兼容配置使用的全局认证入口。

如果绑定非回环地址，应同时设置认证、防火墙和明确的共享范围。不要把开放代理端口
直接暴露到互联网。

`streamSettings` 可为监听 socket 设置 Xray 兼容策略。字段见
[StreamSettings 字段索引](generated/stream.md)。

## 管理面板监听

```yaml
listen:
  panel: 127.0.0.1:9090

ui:
  on: true
  secret: "replace-with-random-token"
```

`panel` 接受：

- 整数端口，主机地址由分享策略和 Profile 决定。
- `host:port` 字符串。

当面板可被非本机访问时，`ui.secret` 是硬性要求。API 功能还要求编译组件
`with_api`。

## 共享策略

| 值 | 行为 |
| --- | --- |
| `false` | 仅本机使用 |
| `true` | 兼容布尔短写，按允许共享处理 |
| `home` | 面向家庭或局域网地址 |
| `all` | 允许绑定所有接口 |

共享策略影响自动选择的监听地址，不替代认证和防火墙。`router` Profile 默认
`home`，因此必须显式配置 `ui.secret`。

## Shadowsocks 入站

要求组件 `with_shadowsocks`。

```yaml
listen:
  shadowsocks:
    address: 0.0.0.0
    port: 8388
    method: aes-256-gcm
    password: "replace-me"
    mode: tcp_and_udp
    handshake-timeout: 10s
    udp-timeout: 5m
    max-connections: 4096
    max-udp-associations: 4096
```

关键规则：

- `port`、`method` 和 `password` 必须提供。
- `users` 用于多用户配置，每项包含 `name` 和 `key`。
- `plugin` 启用 SIP003 服务端插件。插件负责公开监听，内核改为监听插件分配的
  回环地址。
- `plugin-opts` 是插件协议选项，`plugin-args` 是额外进程参数，
  `plugin-startup-timeout` 限制启动等待时间。
- `mode` 决定 TCP、UDP 或两者。资源上限分别限制连接和 UDP association。

密码、用户密钥和插件命令行都可能进入进程环境或诊断输出，部署时按敏感信息处理。

## WireGuard 入站

要求组件 `with_wireguard`。

```yaml
listen:
  wireguard:
    - host: 0.0.0.0
      port: 51820
      privateKey: "server-private-key"
      mtu: 1420
      packetQueue: 1024
      handshakeRateLimit: 1000
      peers:
        - publicKey: "peer-public-key"
          allowedIPs: ["10.20.0.2/32"]
          persistentKeepalive: 25
```

关键规则：

- 服务端 `privateKey` 和每个 Peer 的 `publicKey` 必填。
- `allowedIPs` 同时参与 Peer 识别和包路由，Peer 之间不能产生不明确的归属。
- `presharedKey` 可选，必须与对端一致。
- `reserved` 是三个字节的兼容字段。
- `persistentKeepalive` 单位为秒，适合 NAT 后的 Peer。
- `packetQueue` 限制已认证明文包的排队量。
- `handshakeRateLimit` 在昂贵的密码学处理前限制握手洪泛。

出站字段和协议约束见[WireGuard 指南](../WIREGUARD.md)。

## Young 入站

要求组件 `with_young`。Young 使用 Mozilla Neqo 和 NSS 证书数据库。

```yaml
listen:
  young:
    - host: 0.0.0.0
      port: 443
      nssDatabase: sql:data/nss
      certificateNickname: wuthercore
      authority: example.com
      path: /young
      users: ["replace-me"]
```

`nssDatabase`、`certificateNickname`、`authority` 和 `port` 必填。`path` 是
WebTransport 路径。`clockSkew` 控制认证时间容差。`idleTimeout`、`maxStreams`、
`maxSessions` 和 `maxFlowsPerSession` 限制连接资源。padding 字段必须满足最小值
不大于最大值，Scheme 长度和 decoy 响应由协议实现校验。

协议和证书准备见[Young 指南](../YOUNG_PROTOCOL.md)。

## gRPC 入站

要求组件 `with_grpc`。

```yaml
listen:
  grpc:
    - host: 0.0.0.0
      port: 8443
      protocol: vless
      users: ["00000000-0000-0000-0000-000000000001"]
      security: tls
      grpcSettings:
        serviceName: TunService
        multiMode: false
      tlsSettings:
        certificates:
          - certificateFile: data/tls/fullchain.pem
            keyFile: data/tls/private.key
```

| 字段组 | 说明 |
| --- | --- |
| `protocol`、`users` | 认证后交给内层协议处理 |
| `grpcSettings` | Service name、Tun/TunMulti 模式和 gRPC 元数据 |
| `security` | `none`、`tls` 或 `reality`，必须显式选择安全载波 |
| `tlsSettings` | 完整 TLS、证书、ECH、mTLS、版本和密码套件配置 |
| `realitySettings` | 复用 REALITY 服务端模型，外层覆盖 host、port、protocol、users |
| 资源上限 | 限制连接、Mux session、并发 stream 和 Header List 大小 |
| `trustedXForwardedFor` | 配置信任标记请求头，满足标记后才采用首个 X-Forwarded-For |

存在 TLS 或 REALITY 密钥但 `security` 未选择对应模式时不会静默启用，配置应通过
`check` 明确确认。

## REALITY 入站

要求组件 `with_reality`。

```yaml
listen:
  reality:
    - host: 0.0.0.0
      port: 443
      protocol: vless
      users: ["00000000-0000-0000-0000-000000000001"]
      target: example.com:443
      serverNames: [example.com]
      privateKey: "replace-me"
      shortIds: ["0123456789abcdef"]
      maxTimeDiff: 60000
```

字段分为六组：

1. `host`、`port` 决定监听。
2. `protocol`、`users` 决定认证后的内层协议。
3. `target`、`dest`、`type` 决定伪装目标和兼容目标类型。
4. `serverNames`、`privateKey`、`shortIds` 和 `mldsa65Seed` 决定认证。
5. `minClientVer`、`maxClientVer`、`maxTimeDiff` 决定客户端版本和时间限制。
6. fallback 限速、资源上限和 `streamSettings` 控制抗滥用与底层 socket。

未知字段会被拒绝，避免密钥或限制字段拼错后降级。`maxTimeDiff` 单位为毫秒，
`0` 表示不限制时钟差。私钥和主密钥日志路径属于敏感配置。

## XHTTP 入站

要求组件 `with_xhttp`。`listen.xhttp` 接受单对象或对象列表。监听层包含
`enabled`、host、port、users、TLS、REALITY、CORS、资源限制和完整
`XhttpConfig`。

XHTTP 的字段数量较多，单独阅读：

- [XHTTP 与 StreamSettings](xhttp-stream.md)
- [XHTTP 字段索引](generated/xhttp.md)
- [XHTTP 协议指南](../XHTTP.md)

## 端口和资源冲突

`check` 会在运行计划阶段验证已知的重复监听和不合法端口。启动时仍可能遇到：

- 端口已被其它进程占用。
- 当前用户没有低端口绑定权限。
- IPv4 和 IPv6 dual-stack 行为造成地址冲突。
- 插件先占用或释放端口失败。
- TLS、NSS 或私钥文件无法读取。

生产部署应在目标系统上执行一次前台启动和停止，确认监听创建与资源回收都成功。
