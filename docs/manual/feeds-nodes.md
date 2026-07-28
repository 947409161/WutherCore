---
title: 订阅与节点
description: 订阅源、过滤、重命名、节点短写、结构化节点和传输配置
---

# 订阅与节点

节点可以来自 `feeds` 或 `nodes`。两条路径最终都编译成统一节点列表，再交给分组、
路由、DNS 命名出口和运行时注册器。

完整字段见[订阅与节点字段索引](generated/feeds-nodes.md)。
协议注册器动态解析的 `params`、节点叠加优先级和全协议高级示例见
[高级节点与协议参数](advanced-nodes.md)。

## 数据流

```mermaid
flowchart LR
    Remote["远程订阅"] --> Fetch["下载和缓存"]
    Inline["内联 payload"] --> Detect["格式和协议识别"]
    Fetch --> Decrypt["可选 Age 解密"]
    Decrypt --> Detect
    Detect --> Filter["过滤"]
    Filter --> Rename["重命名"]
    Rename --> Override["字段覆写"]
    Override --> Dedup["去重"]
    Manual["手动 nodes"] --> Compile["节点编译"]
    Dedup --> Compile
    Compile --> Registry["协议注册器"]
```

## `feeds` 的两种写法

URL 短写：

```yaml
feeds:
  primary: https://example.com/subscription
```

对象长写：

```yaml
feeds:
  primary:
    url: https://example.com/subscription
    every: 6h
    via: direct
    size-limit: 8388608
    header:
      User-Agent: WutherCore
      Accept:
        - application/yaml
        - application/json
    keep:
      name_has: [香港, 日本]
    drop:
      name_has: [过期, 剩余]
    rename:
      add_prefix: "[A] "
      remove: ["倍率"]
```

URL 短写等价于只设置 `FeedDetail.url`。对象长写可以同时使用远程 `url` 和内联
`payload`，但实际来源组合和冲突由 `check` 校验。

## 订阅来源字段

| 字段 | 说明 |
| --- | --- |
| `url` | 远程订阅地址 |
| `payload` | 内联节点列表，兼容 `nodes` 和 `outbounds` 别名 |
| `every` | 自动刷新周期 |
| `via` | 下载订阅使用的出站，常用 `direct` |
| `age-secret-key` | 订阅是 ASCII armored Age 文档时用于解密 |
| `size-limit` | 这个 provider 的响应大小上限，`0` 表示不设 provider 专属上限 |
| `header` | 额外 HTTP 请求头，值可为字符串或字符串列表 |
| `filter` | Mihomo 兼容名称或类型包含表达式 |
| `exclude-filter` | Mihomo 兼容名称排除表达式 |
| `exclude-type` | Mihomo 兼容协议类型排除表达式 |
| `keep` | WutherCore 结构化保留过滤器 |
| `drop` | WutherCore 结构化丢弃过滤器 |
| `rename` | 节点名清理和前后缀 |
| `override` | provider 级协议和传输字段覆写 |

## 下载、缓存和解密

`via` 可以引用 `direct` 或真实节点名。引用不存在时配置编译失败。首次启动没有缓存
且远程下载失败时，该订阅不会产生节点。已有缓存时，运行时可按缓存策略继续提供
上次成功内容。

Age 解密只在正文是 ASCII armored Age 文档时执行。配置了 `age-secret-key`
不会强制明文订阅失败。私钥必须视为高敏感信息，不要写入公开示例。

`size-limit` 只增加 provider 专属限制。全局下载安全上限仍然生效，不能通过写
`0` 关闭全局保护。

## 过滤顺序

推荐按下面顺序理解：

1. 解析订阅格式和节点协议。
2. 应用兼容 `filter`、`exclude-filter` 和 `exclude-type`。
3. 应用 `keep` 保留条件。
4. 应用 `drop` 排除条件。
5. 应用 `rename`。
6. 应用 `override`。
7. 按最终节点身份去重。

`FeedFilter` 的字段包括名称包含、协议、国家或地区等结构化条件。空过滤器表示不加
限制。`keep` 与 `drop` 同时出现时，节点先通过保留条件，再检查排除条件。

## 重命名

`FeedRename` 可添加前缀、添加后缀和删除指定文本。重命名发生在分组 `prefer`、
`avoid` 和 API 展示之前，因此分组模式应匹配最终名称。

重命名可能造成两个节点同名。去重会保留确定的一份结果，但不应依赖冲突顺序。
生产配置应让不同来源带稳定前缀。

## provider 覆写

`override` 用于修正订阅缺失或错误的字段。它可以覆盖协议通用参数、代理名称和
REALITY、gRPC、XHTTP 等协议专属设置。

覆写是强操作：

- 它应用到该订阅中所有符合条件的节点。
- 覆写后的字段仍会进入协议注册器严格校验。
- 把 TLS 或 REALITY 设置错误地覆盖到其它协议不会被静默忽略。
- `skip-cert-verify` 会降低证书安全，只用于明确知道风险的环境。

先用 `feeds refresh` 查看解析统计，再通过 `check` 和运行日志验证覆写结果。

## `nodes` 的两种写法

URI 短写：

```yaml
nodes:
  - "socks5://user:password@127.0.0.1:1080#local-socks"
  - "ss://BASE64@203.0.113.10:8388#backup"
```

结构化长写：

```yaml
nodes:
  - name: local-socks
    protocol: socks5
    address: 127.0.0.1:1080
    login:
      user: user
      password: password
    secure:
      tls: false
    transport:
      kind: tcp
    network:
      udp: true
      tfo: false
      ip_family: dual
    params: {}
```

`NodeSpec` 是 untagged 枚举。字符串按 URI 解析，对象按 `NodeDetail` 解析。
对象的 `type` 和 `kind` 是 `protocol` 的兼容别名，`uri` 和 `url` 是 `link`
的兼容别名。

## `NodeDetail` 字段组

| 字段 | 说明 |
| --- | --- |
| `name` | 节点稳定名称，必填 |
| `link` | 可选 URI。存在时先解析 URI，再由对象字段补充或覆盖 |
| `protocol` | 协议名，例如 `socks5`、`shadowsocks`、`vless` |
| `address` | 目标 `host:port` |
| `login` | 用户名、密码、UUID 或其它通用认证材料 |
| `secure` | TLS、SNI、证书校验和 REALITY 客户端设置 |
| `transport` | TCP、WebSocket、gRPC、XHTTP 等传输参数 |
| `network` | UDP、TFO、MPTCP、路由标记和 IP 版本策略 |
| `params` | 协议专属 JSON 值映射 |
| `streamSettings` | Xray 兼容 socket 和 FinalMask 设置 |

通用字段不代表每个协议都会使用。协议注册器会检查必填字段、允许组合和编译组件。
不支持的字段应报错，不能依赖忽略行为。

## 认证字段

`NodeLogin` 提供通用的用户名、密码、UUID 和认证扩展。协议如何解释取决于
`protocol`：

- SOCKS5 和 HTTP 使用用户名与密码。
- VLESS 和 VMess 通常使用 UUID。
- Trojan 和部分其它协议使用密码。
- Shadowsocks 的 cipher 和 password 主要通过协议参数解析。

认证材料会进入运行计划。`explain` 输出共享前必须脱敏。

## 安全字段

`NodeSecure` 管理 TLS 开关、Server Name、证书校验和 REALITY 客户端设置。
REALITY 客户端块包括 fingerprint、serverName、publicKey、shortId、spiderX、
MLDSA65 验证和时间限制等字段。

原则：

- `skip-cert-verify` 默认为关闭。
- Server Name 应与证书或 REALITY 配置一致。
- REALITY public key、short ID 和 fingerprint 必须与服务端匹配。
- 配置了安全字段但二进制缺少 `with_reality` 或 `with_utls` 时会在组件检查或
  协议注册阶段失败。

## 传输字段

`NodeTransport` 是传输入口。常用字段包括传输种类、host、path、Service Name、
HTTP header 和协议专属对象。gRPC 使用 `GrpcTransportSettings`。XHTTP 使用
完整 `XhttpConfig`。

传输和底层 socket 是两层：

- `transport` 决定线上协议封装。
- `streamSettings.sockopt` 决定拨号 socket 的 mark、接口、TFO、Keepalive、
  DNS 地址策略和 Happy Eyeballs。

完整 socket 字段见[StreamSettings 字段索引](generated/stream.md)。

## 协议和组件

`wuther-core components` 显示当前二进制包含的标签。下面是常见映射：

| 配置协议或传输 | 需要的组件 |
| --- | --- |
| HTTP | `with_http` |
| SOCKS | `with_socks` |
| Shadowsocks | `with_shadowsocks` |
| Trojan | `with_trojan` |
| VLESS | `with_vless` |
| VMess | `with_vmess` |
| AnyTLS | `with_anytls` |
| Hysteria | `with_hysteria` |
| Hysteria 2 | `with_hysteria2` |
| TUIC | `with_tuic` |
| WireGuard | `with_wireguard` |
| SSH | `with_ssh` |
| Naive | `with_naive` |
| Young | `with_young` |
| gRPC | `with_grpc` |
| WebSocket | `with_ws` |
| XHTTP | `with_xhttp` |
| QUIC 传输 | `with_quic` |
| REALITY | `with_reality` |
| uTLS | `with_utls` |

完整组件列表和编译选择方式见[组件化构建](../BUILDING.md)。

## 分组引用

分组 `use` 可以引用订阅名和保留入口 `nodes`。引用订阅名时使用该订阅当前解析后的
全部节点。订阅刷新会更新候选集，分组策略随后重新选择。

节点名还可以被 DNS `exits`、路由最终动作、手动分组选择和 API 引用。重命名或删除
节点前应运行 `check`，并审查持久化的 Pin 与手动选择状态。

## 命令行检查

```bash
wuther-core feeds list config.yaml
wuther-core feeds refresh config.yaml --cache-dir data/feeds
wuther-core check config.yaml
wuther-core explain config.yaml
```

`feeds refresh` 验证下载、解密、格式识别和解析统计。`check` 验证静态引用与协议
配置。两者都成功后，仍需实际运行健康检查确认节点可达。

更深入的订阅格式和兼容行为见[自由订阅指南](../FEEDS.md)。
