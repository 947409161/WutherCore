---
title: XHTTP / SplitHTTP 高级字段 完整字段索引
hide:
  - feedback
---

# XHTTP / SplitHTTP 高级字段 完整字段索引

!!! info "由配置源码生成"

    本页由 `scripts/config-reference.py` 从 `core-config` 的公开 Serde
    结构生成，覆盖 YAML/JSON 实际接受的字段、重命名、别名、默认规则和
    枚举写法。修改配置模型后必须重新生成；CI 会拒绝缺字段或过期页面。

XHTTP、下载通道、REALITY、TLS、XMUX、FinalMask 和包变换的完整长尾字段。

全手册当前覆盖 **754 个字段**、**55 个枚举类型**。
行为说明和跨字段约束请同时阅读同分类下的人工手册页面。

## `XhttpListener`

XHTTP 服务端监听配置。 `settings` 直接复用出站使用的完整 [`XhttpConfig`]，不会把字段降级为 `serde_json::Value` 或字符串 map。TLS 的 `cert` / `key` 都是文件路径； 文件读取留给运行时，配置编译阶段负责要求路径非空且成对出现。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1112)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `enabled` | `布尔值` | 可选；默认 `true` | 无 | 无 | 控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1114) |
| `address` | `字符串` | 可选；默认 `127.0.0.1` | `host`<br>`bind` | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1116) |
| `port` | `0-65535 整数` | 必填 | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1117) |
| `cleartext` | `布尔值` | 可选；默认 `false` | 无 | 无 | 明确允许无 TLS 的 HTTP/1.1 或 h2c。默认 false，避免静默降级。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1120) |
| `allow-unauthenticated-non-loopback` | `布尔值` | 可选；默认 `false` | `allow_unauthenticated_non_loopback`<br>`allowUnauthenticatedNonLoopback` | 无 | Raw 服务端尚未提供协议级认证；监听非回环地址时必须显式确认风险。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1128) |
| `tls` | `XhttpListenTls（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpListener` 的 `tls` 参数。解析类型为 `XhttpListenTls（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1130) |
| `alpn` | `XhttpListenAlpn 列表` | 可选；默认 `vec![XhttpListenAlpn::H2, XhttpListenAlpn::Http1]` | 无 | `http/1.1`<br>`h2`<br>`h3` | `XhttpListener` 的 `alpn` 参数。解析类型为 `XhttpListenAlpn 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1132) |
| `target` | `XhttpListenTarget（可选）` | 可选；默认不设置 | 无 | 无 | XHTTP 传输解封后的固定 TCP 目标。 VLESS、VMess、Trojan 等代理协议拥有各自的认证、编解码和 UDP 语义，必须在各协议监听中显式选择 XHTTP 传输；这里不会注册一个 没有真实服务端实现的 `inner-protocol` 枚举。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1139) |
| `tag` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 用于显示、日志和其它配置项引用的稳定名称。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1141) |
| `accept-queue` | `非负整数` | 可选；默认 `256` | `accept_queue`<br>`backlog` | 无 | `XhttpListener` 的 `accept-queue` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1148) |
| `max-active-relays` | `非负整数` | 可选；默认 `256` | `max_active_relays`<br>`maxActiveRelays` | 无 | 单个监听允许同时保持的活动 relay 上限。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1156) |
| `max-active-connections` | `非负整数` | 可选；默认 `1024` | `max_active_connections`<br>`maxActiveConnections` | 无 | 单个监听允许同时保持的底层 TCP/TLS/QUIC 连接上限。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1164) |
| `max-concurrent-streams` | `非负整数` | 可选；默认 `128` | `max_concurrent_streams`<br>`maxConcurrentStreams` | 无 | 单个 H2/H3 底层连接允许同时处理的 HTTP 流上限。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1172) |
| `max-active-http-streams` | `非负整数` | 可选；默认 `1024` | `max_active_http_streams`<br>`maxActiveHttpStreams` | 无 | 单个监听跨全部底层连接允许同时处理的 HTTP 流上限。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1180) |
| `http-idle-timeout` | `时长` | 可选；默认 `90s` | `http_idle_timeout`<br>`httpIdleTimeout` | 无 | 已无活动 HTTP 请求/流时，底层连接可保持空闲的最长时间。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1189) |
| `cors-origins` | `字符串 列表（可选）` | 可选；默认不设置 | `cors_origins`<br>`corsOrigins` | 无 | 浏览器 CORS 策略。缺省时使用 XrayCompatible；显式空数组禁用 CORS； 非空数组为 allowlist，`*` 必须独占。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1199) |
| `streamSettings` | `crate::NodeStreamSettings（可选）` | 可选；默认不设置 | `stream_settings` | 无 | Xray-compatible listener socket policy and final masks. TCP masks are applied before TLS; UDP masks and QUIC parameters are applied below H3. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1203) |
| `settings` | `XhttpConfig` | 可选；使用类型默认值 | `config`<br>`xhttpSettings`<br>`xhttp-settings`<br>`splithttpSettings`<br>`splithttp-settings` | 无 | `XhttpListener` 的 `settings` 参数。解析类型为 `XhttpConfig`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1213) |

## `XhttpListenTarget`

XHTTP Raw 内层透明字节隧道的固定目标。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1219)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `host` | `字符串` | 必填 | `address` | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1221) |
| `port` | `0-65535 整数` | 必填 | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1222) |

## `XhttpListenTls`

`XhttpListenTls` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1227)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `cert` | `字符串（可选）` | 可选；默认不设置 | `certificate`<br>`cert-path`<br>`cert_path` | 无 | 旧版单证书 PEM 路径；与 `certificates` 中的 encipherment 条目互斥。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1237) |
| `key` | `字符串（可选）` | 可选；默认不设置 | `private-key`<br>`private_key`<br>`key-path`<br>`key_path` | 无 | 旧版单私钥 PEM 路径。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1248) |
| `settings（展开）` | `XhttpDownloadTlsSettings` | 可选；使用类型默认值 | 无 | 无 | Xray TLS 全量字段（证书、版本、套件、曲线、ECH、key log 等）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1251) |
| `requireClientCertificate` | `布尔值（可选）` | 可选；默认不设置 | `require-client-certificate`<br>`require_client_certificate` | 无 | 使用 `usage=verify` 证书作为客户端 CA 并强制双向 TLS。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1260) |

## `XhttpRange`

Xray `Int32Range` 的无损配置表示。 接受 JSON/YAML 整数（`64`）或范围字符串（`"64-128"`），序列化时使用 同样的规范形式。XHTTP 的范围均为非负 int32；反向范围和溢出值直接报错， 不做静默交换。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1828)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `from` | `非负整数` | 必填 | 无 | 无 | `XhttpRange` 的 `from` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1829) |
| `to` | `非负整数` | 必填 | 无 | 无 | `XhttpRange` 的 `to` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1830) |

## `XhttpXmuxConfig`

`XhttpXmuxConfig` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1948)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `maxConcurrency` | `XhttpRange（可选）` | 可选；默认不设置 | `max-concurrency`<br>`max_concurrency` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1956) |
| `maxConnections` | `XhttpRange（可选）` | 可选；默认不设置 | `max-connections`<br>`max_connections` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1964) |
| `cMaxReuseTimes` | `XhttpRange（可选）` | 可选；默认不设置 | `c-max-reuse-times`<br>`c_max_reuse_times` | 无 | `XhttpXmuxConfig` 的 `cMaxReuseTimes` 参数。解析类型为 `XhttpRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1972) |
| `hMaxRequestTimes` | `XhttpRange（可选）` | 可选；默认不设置 | `h-max-request-times`<br>`h_max_request_times` | 无 | `XhttpXmuxConfig` 的 `hMaxRequestTimes` 参数。解析类型为 `XhttpRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1980) |
| `hMaxReusableSecs` | `XhttpRange（可选）` | 可选；默认不设置 | `h-max-reusable-secs`<br>`h_max_reusable_secs` | 无 | `XhttpXmuxConfig` 的 `hMaxReusableSecs` 参数。解析类型为 `XhttpRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1988) |
| `hKeepAlivePeriod` | `整数（可选）` | 可选；默认不设置 | `h-keep-alive-period`<br>`h_keep_alive_period` | 无 | `XhttpXmuxConfig` 的 `hKeepAlivePeriod` 参数。解析类型为 `整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1996) |

## `XhttpSignedRange`

Xray finalmask 使用的有符号范围。接受整数或 `"from-to"` 字符串。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2001)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `left` | `整数` | 必填 | 无 | 无 | `XhttpSignedRange` 的 `left` 参数。解析类型为 `整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2002) |
| `right` | `整数` | 必填 | 无 | 无 | `XhttpSignedRange` 的 `right` 参数。解析类型为 `整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2003) |

## `XhttpDownloadTlsCertificate`

`XhttpDownloadTlsCertificate` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2118)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `certificateFile` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 文件或 URL 路径；相对路径按运行进程的工作目录解析。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2124) |
| `certificate` | `字符串 列表（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadTlsCertificate` 的 `certificate` 参数。解析类型为 `字符串 列表（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2126) |
| `keyFile` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 文件或 URL 路径；相对路径按运行进程的工作目录解析。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2128) |
| `key` | `字符串 列表（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadTlsCertificate` 的 `key` 参数。解析类型为 `字符串 列表（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2130) |
| `usage` | `XhttpTlsCertificateUsage（可选）` | 可选；默认不设置 | 无 | `encipherment`<br>`verify`<br>`issue` | `XhttpDownloadTlsCertificate` 的 `usage` 参数。解析类型为 `XhttpTlsCertificateUsage（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2132) |
| `ocspStapling` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadTlsCertificate` 的 `ocspStapling` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2138) |
| `oneTimeLoading` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadTlsCertificate` 的 `oneTimeLoading` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2144) |
| `buildChain` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadTlsCertificate` 的 `buildChain` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2150) |

## `XhttpDownloadCustomSockopt`

`XhttpDownloadCustomSockopt` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2155)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `system` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadCustomSockopt` 的 `system` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2157) |
| `network` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadCustomSockopt` 的 `network` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2159) |
| `level` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadCustomSockopt` 的 `level` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2161) |
| `opt` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadCustomSockopt` 的 `opt` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2163) |
| `value` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadCustomSockopt` 的 `value` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2165) |
| `type` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadCustomSockopt` 的 `type` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2167) |

## `XhttpDownloadHappyEyeballs`

`XhttpDownloadHappyEyeballs` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2172)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `prioritizeIPv6` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadHappyEyeballs` 的 `prioritizeIPv6` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2178) |
| `tryDelayMs` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadHappyEyeballs` 的 `tryDelayMs` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2184) |
| `interleave` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadHappyEyeballs` 的 `interleave` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2186) |
| `maxConcurrentTry` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2192) |

## `XhttpMaskTransformArg`

`XhttpMaskTransformArg` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2284)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `type` | `XhttpMaskPacketEncoding（可选）` | 可选；默认不设置 | 无 | `array`<br>`str`<br>`hex`<br>`base64` | `XhttpMaskTransformArg` 的 `type` 参数。解析类型为 `XhttpMaskPacketEncoding（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2286) |
| `bytes` | `XhttpMaskPacket（可选）` | 可选；默认不设置 | 无 | `Bytes(Vec<u8>)`<br>`Text(String)` | `XhttpMaskTransformArg` 的 `bytes` 参数。解析类型为 `XhttpMaskPacket（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2288) |
| `u64` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskTransformArg` 的 `u64` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2290) |
| `reuse` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskTransformArg` 的 `reuse` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2292) |
| `metadata` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskTransformArg` 的 `metadata` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2294) |
| `transform` | `XhttpMaskTransform（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskTransformArg` 的 `transform` 参数。解析类型为 `XhttpMaskTransform（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2296) |

## `XhttpMaskTransform`

`XhttpMaskTransform` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2301)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `op` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskTransform` 的 `op` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2303) |
| `args` | `XhttpMaskTransformArg 列表` | 可选；默认空 | 无 | 无 | `XhttpMaskTransform` 的 `args` 参数。解析类型为 `XhttpMaskTransformArg 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2305) |

## `XhttpMaskTcpItem`

`XhttpMaskTcpItem` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2310)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `delay` | `XhttpSignedRange（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskTcpItem` 的 `delay` 参数。解析类型为 `XhttpSignedRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2312) |
| `rand` | `整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskTcpItem` 的 `rand` 参数。解析类型为 `整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2314) |
| `randRange` | `XhttpSignedRange（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskTcpItem` 的 `randRange` 参数。解析类型为 `XhttpSignedRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2316) |
| `capture` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskTcpItem` 的 `capture` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2318) |
| `type` | `XhttpMaskPacketEncoding（可选）` | 可选；默认不设置 | 无 | `array`<br>`str`<br>`hex`<br>`base64` | `XhttpMaskTcpItem` 的 `type` 参数。解析类型为 `XhttpMaskPacketEncoding（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2320) |
| `reuse` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskTcpItem` 的 `reuse` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2322) |
| `transform` | `XhttpMaskTransform（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskTcpItem` 的 `transform` 参数。解析类型为 `XhttpMaskTransform（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2324) |
| `packet` | `XhttpMaskPacket（可选）` | 可选；默认不设置 | 无 | `Bytes(Vec<u8>)`<br>`Text(String)` | `XhttpMaskTcpItem` 的 `packet` 参数。解析类型为 `XhttpMaskPacket（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2326) |

## `XhttpHeaderCustomTcp`

`XhttpHeaderCustomTcp` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2331)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `clients` | `Vec<XhttpMaskTcpItem> 列表` | 可选；默认空 | 无 | 无 | `XhttpHeaderCustomTcp` 的 `clients` 参数。解析类型为 `Vec<XhttpMaskTcpItem> 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2333) |
| `servers` | `Vec<XhttpMaskTcpItem> 列表` | 可选；默认空 | 无 | 无 | `XhttpHeaderCustomTcp` 的 `servers` 参数。解析类型为 `Vec<XhttpMaskTcpItem> 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2335) |
| `errors` | `Vec<XhttpMaskTcpItem> 列表` | 可选；默认空 | 无 | 无 | `XhttpHeaderCustomTcp` 的 `errors` 参数。解析类型为 `Vec<XhttpMaskTcpItem> 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2337) |

## `XhttpFragmentMask`

`XhttpFragmentMask` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2342)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `packets` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpFragmentMask` 的 `packets` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2344) |
| `length` | `XhttpSignedRange（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpFragmentMask` 的 `length` 参数。解析类型为 `XhttpSignedRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2346) |
| `delay` | `XhttpSignedRange（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpFragmentMask` 的 `delay` 参数。解析类型为 `XhttpSignedRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2348) |
| `lengths` | `XhttpSignedRange 列表` | 可选；默认空 | 无 | 无 | `XhttpFragmentMask` 的 `lengths` 参数。解析类型为 `XhttpSignedRange 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2350) |
| `delays` | `XhttpSignedRange 列表` | 可选；默认空 | 无 | 无 | `XhttpFragmentMask` 的 `delays` 参数。解析类型为 `XhttpSignedRange 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2352) |
| `maxSplit` | `XhttpSignedRange（可选）` | 可选；默认不设置 | 无 | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2354) |

## `XhttpSudokuMask`

`XhttpSudokuMask` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2359)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `password` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2361) |
| `ascii` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpSudokuMask` 的 `ascii` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2363) |
| `customTable` | `字符串（可选）` | 可选；默认不设置 | `custom_table` | 无 | `XhttpSudokuMask` 的 `customTable` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2370) |
| `customTables` | `字符串 列表` | 可选；默认空 | `custom_tables` | 无 | `XhttpSudokuMask` 的 `customTables` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2377) |
| `paddingMin` | `非负整数（可选）` | 可选；默认不设置 | `padding_min` | 无 | `XhttpSudokuMask` 的 `paddingMin` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2384) |
| `paddingMax` | `非负整数（可选）` | 可选；默认不设置 | `padding_max` | 无 | `XhttpSudokuMask` 的 `paddingMax` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2391) |

## `XhttpXmcMask`

`XhttpXmcMask` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2396)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `hostname` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpXmcMask` 的 `hostname` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2398) |
| `usernames` | `字符串 列表` | 可选；默认空 | 无 | 无 | `XhttpXmcMask` 的 `usernames` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2400) |
| `password` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2402) |

## `XhttpMaskUdpItem`

`XhttpMaskUdpItem` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2432)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `rand` | `整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskUdpItem` 的 `rand` 参数。解析类型为 `整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2434) |
| `randRange` | `XhttpSignedRange（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskUdpItem` 的 `randRange` 参数。解析类型为 `XhttpSignedRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2436) |
| `capture` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskUdpItem` 的 `capture` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2438) |
| `type` | `XhttpMaskPacketEncoding（可选）` | 可选；默认不设置 | 无 | `array`<br>`str`<br>`hex`<br>`base64` | `XhttpMaskUdpItem` 的 `type` 参数。解析类型为 `XhttpMaskPacketEncoding（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2440) |
| `reuse` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskUdpItem` 的 `reuse` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2442) |
| `transform` | `XhttpMaskTransform（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMaskUdpItem` 的 `transform` 参数。解析类型为 `XhttpMaskTransform（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2444) |
| `packet` | `XhttpMaskPacket（可选）` | 可选；默认不设置 | 无 | `Bytes(Vec<u8>)`<br>`Text(String)` | `XhttpMaskUdpItem` 的 `packet` 参数。解析类型为 `XhttpMaskPacket（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2446) |

## `XhttpHeaderCustomUdp`

`XhttpHeaderCustomUdp` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2451)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `mode` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpHeaderCustomUdp` 的 `mode` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2453) |
| `client` | `XhttpMaskUdpItem 列表` | 可选；默认空 | 无 | 无 | `XhttpHeaderCustomUdp` 的 `client` 参数。解析类型为 `XhttpMaskUdpItem 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2455) |
| `server` | `XhttpMaskUdpItem 列表` | 可选；默认空 | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2457) |

## `XhttpMkcpLegacyMask`

`XhttpMkcpLegacyMask` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2462)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `header` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMkcpLegacyMask` 的 `header` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2464) |
| `value` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpMkcpLegacyMask` 的 `value` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2466) |

## `XhttpNoiseItem`

`XhttpNoiseItem` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2471)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `rand` | `XhttpSignedRange（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpNoiseItem` 的 `rand` 参数。解析类型为 `XhttpSignedRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2473) |
| `randRange` | `XhttpSignedRange（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpNoiseItem` 的 `randRange` 参数。解析类型为 `XhttpSignedRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2475) |
| `type` | `XhttpMaskPacketEncoding（可选）` | 可选；默认不设置 | 无 | `array`<br>`str`<br>`hex`<br>`base64` | `XhttpNoiseItem` 的 `type` 参数。解析类型为 `XhttpMaskPacketEncoding（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2477) |
| `packet` | `XhttpMaskPacket（可选）` | 可选；默认不设置 | 无 | `Bytes(Vec<u8>)`<br>`Text(String)` | `XhttpNoiseItem` 的 `packet` 参数。解析类型为 `XhttpMaskPacket（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2479) |
| `delay` | `XhttpSignedRange（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpNoiseItem` 的 `delay` 参数。解析类型为 `XhttpSignedRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2481) |

## `XhttpNoiseMask`

`XhttpNoiseMask` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2486)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `reset` | `XhttpSignedRange（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpNoiseMask` 的 `reset` 参数。解析类型为 `XhttpSignedRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2488) |
| `noise` | `XhttpNoiseItem 列表` | 可选；默认空 | 无 | 无 | `XhttpNoiseMask` 的 `noise` 参数。解析类型为 `XhttpNoiseItem 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2490) |

## `XhttpSalamanderMask`

`XhttpSalamanderMask` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2495)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `password` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2497) |
| `packetSize` | `XhttpSignedRange（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpSalamanderMask` 的 `packetSize` 参数。解析类型为 `XhttpSignedRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2503) |

## `XhttpXdnsMask`

`XhttpXdnsMask` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2508)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `domain` | `XhttpMaskDomain（可选）` | 可选；默认不设置 | 无 | `One(String)`<br>`Many(Vec<String>)` | `XhttpXdnsMask` 的 `domain` 参数。解析类型为 `XhttpMaskDomain（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2510) |
| `domains` | `字符串 列表` | 可选；默认空 | 无 | 无 | `XhttpXdnsMask` 的 `domains` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2512) |
| `resolvers` | `字符串 列表` | 可选；默认空 | 无 | 无 | `XhttpXdnsMask` 的 `resolvers` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2514) |

## `XhttpXicmpMask`

`XhttpXicmpMask` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2519)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `dgram` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpXicmpMask` 的 `dgram` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2521) |
| `ips` | `字符串 列表` | 可选；默认空 | 无 | 无 | `XhttpXicmpMask` 的 `ips` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2523) |

## `XhttpRealmMask`

`XhttpRealmMask` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2528)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `url` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpRealmMask` 的 `url` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2530) |
| `stunServers` | `字符串 列表` | 可选；默认空 | 无 | 无 | `XhttpRealmMask` 的 `stunServers` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2532) |
| `tlsConfig` | `XhttpDownloadTlsSettings（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpRealmMask` 的 `tlsConfig` 参数。解析类型为 `XhttpDownloadTlsSettings（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2534) |

## `XhttpUdpHop`

`XhttpUdpHop` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2584)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `ports` | `XhttpPortList（可选）` | 可选；默认不设置 | 无 | `One(u16)`<br>`List(String)` | `XhttpUdpHop` 的 `ports` 参数。解析类型为 `XhttpPortList（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2586) |
| `interval` | `XhttpSignedRange（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpUdpHop` 的 `interval` 参数。解析类型为 `XhttpSignedRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2588) |

## `XhttpQuicParams`

`XhttpQuicParams` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2593)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `congestion` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpQuicParams` 的 `congestion` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2595) |
| `debug` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpQuicParams` 的 `debug` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2597) |
| `bbrProfile` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpQuicParams` 的 `bbrProfile` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2603) |
| `brutalUp` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpQuicParams` 的 `brutalUp` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2605) |
| `brutalDown` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpQuicParams` 的 `brutalDown` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2611) |
| `udpHop` | `XhttpUdpHop（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpQuicParams` 的 `udpHop` 参数。解析类型为 `XhttpUdpHop（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2613) |
| `initStreamReceiveWindow` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpQuicParams` 的 `initStreamReceiveWindow` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2619) |
| `maxStreamReceiveWindow` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2625) |
| `initConnectionReceiveWindow` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpQuicParams` 的 `initConnectionReceiveWindow` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2631) |
| `maxConnectionReceiveWindow` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2637) |
| `maxIdleTimeout` | `整数（可选）` | 可选；默认不设置 | 无 | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2643) |
| `keepAlivePeriod` | `整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpQuicParams` 的 `keepAlivePeriod` 参数。解析类型为 `整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2649) |
| `disablePathMTUDiscovery` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpQuicParams` 的 `disablePathMTUDiscovery` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2655) |
| `maxIncomingStreams` | `整数（可选）` | 可选；默认不设置 | 无 | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2661) |

## `XhttpFinalMask`

`XhttpFinalMask` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2666)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `tcp` | `XhttpTcpMask 列表` | 可选；默认空 | 无 | `header-custom{ #[serde(default)] settings: XhttpHeaderCustomTcp, }`<br>`fragment{ #[serde(default)] settings: XhttpFragmentMask, }`<br>`sudoku{ #[serde(default)] settings: XhttpSudokuMask, }`<br>`xmc{ #[serde(default)] settings: XhttpXmcMask, }` | `XhttpFinalMask` 的 `tcp` 参数。解析类型为 `XhttpTcpMask 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2668) |
| `udp` | `XhttpUdpMask 列表` | 可选；默认空 | 无 | `header-custom{ #[serde(default)] settings: XhttpHeaderCustomUdp, }`<br>`mkcp-legacy{ #[serde(default)] settings: XhttpMkcpLegacyMask, }`<br>`noise{ #[serde(default)] settings: XhttpNoiseMask, }`<br>`salamander{ #[serde(default)] settings: XhttpSalamanderMask, }`<br>`sudoku{ #[serde(default)] settings: XhttpSudokuMask, }`<br>`xdns{ #[serde(default)] settings: XhttpXdnsMask, }`<br>`xicmp{ #[serde(default)] settings: XhttpXicmpMask, }`<br>`realm{ #[serde(default)] settings: XhttpRealmMask, }` | `XhttpFinalMask` 的 `udp` 参数。解析类型为 `XhttpUdpMask 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2670) |
| `quicParams` | `XhttpQuicParams（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpFinalMask` 的 `quicParams` 参数。解析类型为 `XhttpQuicParams（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2676) |

## `XhttpDownloadTlsSettings`

`XhttpDownloadTlsSettings` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2681)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `certificates` | `XhttpDownloadTlsCertificate 列表` | 可选；默认空 | 无 | 无 | `XhttpDownloadTlsSettings` 的 `certificates` 参数。解析类型为 `XhttpDownloadTlsCertificate 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2683) |
| `serverName` | `字符串（可选）` | 可选；默认不设置 | `server-name`<br>`server_name`<br>`sni` | 无 | `XhttpDownloadTlsSettings` 的 `serverName` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2692) |
| `allowInsecure` | `布尔值（可选）` | 可选；默认不设置 | `allow-insecure`<br>`allow_insecure`<br>`insecure`<br>`skip-cert-verify` | 无 | `XhttpDownloadTlsSettings` 的 `allowInsecure` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2702) |
| `alpn` | `字符串 列表（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadTlsSettings` 的 `alpn` 参数。解析类型为 `字符串 列表（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2708) |
| `enableSessionResumption` | `布尔值（可选）` | 可选；默认不设置 | `enable-session-resumption`<br>`enable_session_resumption` | 无 | `XhttpDownloadTlsSettings` 的 `enableSessionResumption` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2716) |
| `disableSystemRoot` | `布尔值（可选）` | 可选；默认不设置 | `disable-system-root`<br>`disable_system_root` | 无 | `XhttpDownloadTlsSettings` 的 `disableSystemRoot` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2724) |
| `minVersion` | `字符串（可选）` | 可选；默认不设置 | `min-version`<br>`min_version` | 无 | 对应范围或资源量的下限。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2732) |
| `maxVersion` | `字符串（可选）` | 可选；默认不设置 | `max-version`<br>`max_version` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2740) |
| `cipherSuites` | `字符串（可选）` | 可选；默认不设置 | `cipher-suites`<br>`cipher_suites` | 无 | `XhttpDownloadTlsSettings` 的 `cipherSuites` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2748) |
| `fingerprint` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadTlsSettings` 的 `fingerprint` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2750) |
| `rejectUnknownSni` | `布尔值（可选）` | 可选；默认不设置 | `rejectUnknownSNI`<br>`reject-unknown-sni`<br>`reject_unknown_sni` | 无 | `XhttpDownloadTlsSettings` 的 `rejectUnknownSni` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2759) |
| `curvePreferences` | `字符串 列表（可选）` | 可选；默认不设置 | `curve-preferences`<br>`curve_preferences` | 无 | `XhttpDownloadTlsSettings` 的 `curvePreferences` 参数。解析类型为 `字符串 列表（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2768) |
| `masterKeyLog` | `字符串（可选）` | 可选；默认不设置 | `master-key-log`<br>`master_key_log` | 无 | `XhttpDownloadTlsSettings` 的 `masterKeyLog` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2776) |
| `pinnedPeerCertSha256` | `字符串（可选）` | 可选；默认不设置 | `pinned-peer-cert-sha256`<br>`pinned_peer_cert_sha256` | 无 | `XhttpDownloadTlsSettings` 的 `pinnedPeerCertSha256` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2784) |
| `verifyPeerCertByName` | `字符串（可选）` | 可选；默认不设置 | `verify-peer-cert-by-name`<br>`verify_peer_cert_by_name` | 无 | `XhttpDownloadTlsSettings` 的 `verifyPeerCertByName` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2792) |
| `echServerKeys` | `字符串（可选）` | 可选；默认不设置 | `ech-server-keys`<br>`ech_server_keys` | 无 | `XhttpDownloadTlsSettings` 的 `echServerKeys` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2800) |
| `echConfigList` | `字符串（可选）` | 可选；默认不设置 | `ech-config-list`<br>`ech_config_list` | 无 | `XhttpDownloadTlsSettings` 的 `echConfigList` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2808) |
| `echSockopt` | `XhttpDownloadSocketSettings（可选）` | 可选；默认不设置 | `ech-sockopt`<br>`ech_sockopt`<br>`echSocketSettings`<br>`ech-socket-settings`<br>`ech_socket_settings` | 无 | `XhttpDownloadTlsSettings` 的 `echSockopt` 参数。解析类型为 `XhttpDownloadSocketSettings（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2819) |

## `XhttpRealityLimitFallback`

`XhttpRealityLimitFallback` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3189)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `afterBytes` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpRealityLimitFallback` 的 `afterBytes` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3195) |
| `bytesPerSec` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpRealityLimitFallback` 的 `bytesPerSec` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3201) |
| `burstBytesPerSec` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpRealityLimitFallback` 的 `burstBytesPerSec` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3207) |

## `XhttpDownloadRealitySettings`

`XhttpDownloadRealitySettings` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3212)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `masterKeyLog` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadRealitySettings` 的 `masterKeyLog` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3218) |
| `show` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadRealitySettings` 的 `show` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3220) |
| `target` | `XhttpRealityTarget（可选）` | 可选；默认不设置 | 无 | `Port(u16)`<br>`Address(String)` | `XhttpDownloadRealitySettings` 的 `target` 参数。解析类型为 `XhttpRealityTarget（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3222) |
| `dest` | `XhttpRealityTarget（可选）` | 可选；默认不设置 | 无 | `Port(u16)`<br>`Address(String)` | `XhttpDownloadRealitySettings` 的 `dest` 参数。解析类型为 `XhttpRealityTarget（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3224) |
| `type` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadRealitySettings` 的 `type` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3226) |
| `xver` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadRealitySettings` 的 `xver` 参数。解析类型为 `非负整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3228) |
| `serverNames` | `字符串 列表` | 可选；默认空 | 无 | 无 | `XhttpDownloadRealitySettings` 的 `serverNames` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3230) |
| `privateKey` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3236) |
| `minClientVer` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 对应范围或资源量的下限。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3242) |
| `maxClientVer` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3248) |
| `maxTimeDiff` | `非负整数（可选）` | 可选；默认不设置 | 无 | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3254) |
| `shortIds` | `字符串 列表` | 可选；默认空 | 无 | 无 | `XhttpDownloadRealitySettings` 的 `shortIds` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3256) |
| `mldsa65Seed` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadRealitySettings` 的 `mldsa65Seed` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3262) |
| `limitFallbackUpload` | `XhttpRealityLimitFallback（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadRealitySettings` 的 `limitFallbackUpload` 参数。解析类型为 `XhttpRealityLimitFallback（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3268) |
| `limitFallbackDownload` | `XhttpRealityLimitFallback（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadRealitySettings` 的 `limitFallbackDownload` 参数。解析类型为 `XhttpRealityLimitFallback（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3274) |
| `serverName` | `字符串（可选）` | 可选；默认不设置 | `server-name`<br>`server_name`<br>`sni` | 无 | `XhttpDownloadRealitySettings` 的 `serverName` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3283) |
| `password` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3285) |
| `publicKey` | `字符串（可选）` | 可选；默认不设置 | `public-key`<br>`public_key` | 无 | `XhttpDownloadRealitySettings` 的 `publicKey` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3293) |
| `shortId` | `字符串（可选）` | 可选；默认不设置 | `short-id`<br>`short_id` | 无 | `XhttpDownloadRealitySettings` 的 `shortId` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3301) |
| `fingerprint` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadRealitySettings` 的 `fingerprint` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3303) |
| `mldsa65Verify` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadRealitySettings` 的 `mldsa65Verify` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3309) |
| `spiderX` | `字符串（可选）` | 可选；默认不设置 | `spider-x`<br>`spider_x` | 无 | `XhttpDownloadRealitySettings` 的 `spiderX` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3317) |

## `XhttpDownloadSocketSettings`

`XhttpDownloadSocketSettings` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3322)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `mark` | `整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadSocketSettings` 的 `mark` 参数。解析类型为 `整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3324) |
| `tcpFastOpen` | `XhttpTcpFastOpen（可选）` | 可选；默认不设置 | `tfo` | `Enabled(bool)`<br>`QueueLength(i32)` | `XhttpDownloadSocketSettings` 的 `tcpFastOpen` 参数。解析类型为 `XhttpTcpFastOpen（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3331) |
| `tproxy` | `XhttpTproxyMode（可选）` | 可选；默认不设置 | 无 | `off`<br>`tproxy`<br>`redirect` | `XhttpDownloadSocketSettings` 的 `tproxy` 参数。解析类型为 `XhttpTproxyMode（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3333) |
| `acceptProxyProtocol` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadSocketSettings` 的 `acceptProxyProtocol` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3339) |
| `tcpMptcp` | `布尔值（可选）` | 可选；默认不设置 | `tcp-mptcp`<br>`tcp_mptcp`<br>`mptcp` | 无 | `XhttpDownloadSocketSettings` 的 `tcpMptcp` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3348) |
| `v6only` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadSocketSettings` 的 `v6only` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3350) |
| `interface` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadSocketSettings` 的 `interface` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3352) |
| `domainStrategy` | `XhttpDomainStrategy（可选）` | 可选；默认不设置 | `domain-strategy`<br>`domain_strategy`<br>`ip-family`<br>`ip_family` | `AsIs`<br>`UseIP`<br>`UseIPv4`<br>`UseIPv6`<br>`UseIPv4v6`<br>`UseIPv6v4`<br>`ForceIP`<br>`ForceIPv4`<br>`ForceIPv6`<br>`ForceIPv4v6`<br>`ForceIPv6v4` | `XhttpDownloadSocketSettings` 的 `domainStrategy` 参数。解析类型为 `XhttpDomainStrategy（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3362) |
| `dialerProxy` | `字符串（可选）` | 可选；默认不设置 | `dialer-proxy`<br>`dialer_proxy` | 无 | `XhttpDownloadSocketSettings` 的 `dialerProxy` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3370) |
| `tcpKeepAliveInterval` | `整数（可选）` | 可选；默认不设置 | `tcp-keep-alive-interval`<br>`tcp_keep_alive_interval` | 无 | 周期性任务的执行间隔；时长字段接受 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3378) |
| `tcpKeepAliveIdle` | `整数（可选）` | 可选；默认不设置 | `tcp-keep-alive-idle`<br>`tcp_keep_alive_idle` | 无 | `XhttpDownloadSocketSettings` 的 `tcpKeepAliveIdle` 参数。解析类型为 `整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3386) |
| `tcpWindowClamp` | `整数（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadSocketSettings` 的 `tcpWindowClamp` 参数。解析类型为 `整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3392) |
| `tcpUserTimeout` | `整数（可选）` | 可选；默认不设置 | `tcp-user-timeout`<br>`tcp_user_timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3400) |
| `tcpMaxSeg` | `整数（可选）` | 可选；默认不设置 | `tcp-max-seg`<br>`tcp_max_seg` | 无 | `XhttpDownloadSocketSettings` 的 `tcpMaxSeg` 参数。解析类型为 `整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3408) |
| `tcpCongestion` | `字符串（可选）` | 可选；默认不设置 | `tcp-congestion`<br>`tcp_congestion` | 无 | `XhttpDownloadSocketSettings` 的 `tcpCongestion` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3416) |
| `penetrate` | `布尔值（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadSocketSettings` 的 `penetrate` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3418) |
| `customSockopt` | `XhttpDownloadCustomSockopt 列表` | 可选；默认空 | 无 | 无 | `XhttpDownloadSocketSettings` 的 `customSockopt` 参数。解析类型为 `XhttpDownloadCustomSockopt 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3424) |
| `addressPortStrategy` | `XhttpAddressPortStrategy（可选）` | 可选；默认不设置 | 无 | `none`<br>`srvPortOnly`<br>`srvAddressOnly`<br>`srvPortAndAddress`<br>`txtPortOnly`<br>`txtAddressOnly`<br>`txtPortAndAddress` | `XhttpDownloadSocketSettings` 的 `addressPortStrategy` 参数。解析类型为 `XhttpAddressPortStrategy（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3430) |
| `happyEyeballs` | `XhttpDownloadHappyEyeballs（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadSocketSettings` 的 `happyEyeballs` 参数。解析类型为 `XhttpDownloadHappyEyeballs（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3436) |
| `trustedXForwardedFor` | `字符串 列表` | 可选；默认空 | 无 | 无 | `XhttpDownloadSocketSettings` 的 `trustedXForwardedFor` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3442) |

## `XhttpDownloadSettings`

Xray `internet.StreamConfig` 在 XHTTP `downloadSettings` 中可执行的强类型子集。 下载方向可指定独立目标、传输和安全参数；`xhttpSettings` 与 `transport.xhttp` 都是强类型 XHTTP 配置。兼容输入可同时提供两种别名， 但解析 `extra` 后的有效配置必须等价。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3452)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `address` | `字符串（可选）` | 可选；默认不设置 | `server` | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3454) |
| `host` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3456) |
| `port` | `0-65535 整数（可选）` | 可选；默认不设置 | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3458) |
| `method` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadSettings` 的 `method` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3460) |
| `network` | `字符串（可选）` | 可选；默认不设置 | `protocolName`<br>`protocol-name`<br>`protocol_name` | 无 | `XhttpDownloadSettings` 的 `network` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3468) |
| `transport` | `NodeTransport（可选）` | 可选；默认不设置 | `transportSettings`<br>`transport-settings`<br>`transport_settings` | 无 | `XhttpDownloadSettings` 的 `transport` 参数。解析类型为 `NodeTransport（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3476) |
| `xhttpSettings` | `XhttpConfig（可选）` | 可选；默认不设置 | `xhttp-settings`<br>`splithttpSettings`<br>`splithttp-settings` | 无 | `XhttpDownloadSettings` 的 `xhttpSettings` 参数。解析类型为 `XhttpConfig（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3485) |
| `security` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadSettings` 的 `security` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3487) |
| `tlsSettings` | `XhttpDownloadTlsSettings（可选）` | 可选；默认不设置 | `tls-settings`<br>`tls_settings` | 无 | `XhttpDownloadSettings` 的 `tlsSettings` 参数。解析类型为 `XhttpDownloadTlsSettings（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3495) |
| `realitySettings` | `XhttpDownloadRealitySettings（可选）` | 可选；默认不设置 | `reality-settings`<br>`reality_settings` | 无 | `XhttpDownloadSettings` 的 `realitySettings` 参数。解析类型为 `XhttpDownloadRealitySettings（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3503) |
| `alpn` | `字符串 列表（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpDownloadSettings` 的 `alpn` 参数。解析类型为 `字符串 列表（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3509) |
| `sockopt` | `XhttpDownloadSocketSettings（可选）` | 可选；默认不设置 | `socketSettings`<br>`socket-settings`<br>`socket_settings` | 无 | `XhttpDownloadSettings` 的 `sockopt` 参数。解析类型为 `XhttpDownloadSocketSettings（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3518) |
| `finalmask` | `XhttpFinalMask（可选）` | 可选；默认不设置 | `finalMask` | 无 | `XhttpDownloadSettings` 的 `finalmask` 参数。解析类型为 `XhttpFinalMask（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3525) |

## `XhttpConfig`

Xray XHTTP/SplitHTTP 完整配置。 字段规范名使用 Xray JSON camelCase；同时接受 Friendly YAML 使用过的 kebab-case 与早期 snake_case 名称。没有 `Value`/任意 map 逃生字段。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3534)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `host` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3536) |
| `path` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 文件或 URL 路径；相对路径按运行进程的工作目录解析。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3538) |
| `mode` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpConfig` 的 `mode` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3540) |
| `headers` | `名称 → 字符串 映射（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpConfig` 的 `headers` 参数。解析类型为 `名称 → 字符串 映射（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3542) |
| `xPaddingBytes` | `XhttpRange（可选）` | 可选；默认不设置 | `x-padding-bytes`<br>`x_padding_bytes` | 无 | `XhttpConfig` 的 `xPaddingBytes` 参数。解析类型为 `XhttpRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3550) |
| `xPaddingObfsMode` | `布尔值（可选）` | 可选；默认不设置 | `x-padding-obfs-mode`<br>`x_padding_obfs_mode` | 无 | `XhttpConfig` 的 `xPaddingObfsMode` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3558) |
| `xPaddingKey` | `字符串（可选）` | 可选；默认不设置 | `x-padding-key`<br>`x_padding_key` | 无 | `XhttpConfig` 的 `xPaddingKey` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3566) |
| `xPaddingHeader` | `字符串（可选）` | 可选；默认不设置 | `x-padding-header`<br>`x_padding_header` | 无 | `XhttpConfig` 的 `xPaddingHeader` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3574) |
| `xPaddingPlacement` | `字符串（可选）` | 可选；默认不设置 | `x-padding-placement`<br>`x_padding_placement` | 无 | `XhttpConfig` 的 `xPaddingPlacement` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3582) |
| `xPaddingMethod` | `字符串（可选）` | 可选；默认不设置 | `x-padding-method`<br>`x_padding_method` | 无 | `XhttpConfig` 的 `xPaddingMethod` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3590) |
| `uplinkHTTPMethod` | `字符串（可选）` | 可选；默认不设置 | `uplinkHttpMethod`<br>`uplink-http-method`<br>`uplink_http_method` | 无 | `XhttpConfig` 的 `uplinkHTTPMethod` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3599) |
| `sessionIDPlacement` | `字符串（可选）` | 可选；默认不设置 | `sessionIdPlacement`<br>`session-placement`<br>`session-id-placement`<br>`session_id_placement` | 无 | `XhttpConfig` 的 `sessionIDPlacement` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3609) |
| `sessionIDKey` | `字符串（可选）` | 可选；默认不设置 | `sessionIdKey`<br>`session-key`<br>`session-id-key`<br>`session_id_key` | 无 | `XhttpConfig` 的 `sessionIDKey` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3619) |
| `sessionIDTable` | `字符串（可选）` | 可选；默认不设置 | `sessionIdTable`<br>`session-table`<br>`session-id-table`<br>`session_id_table` | 无 | `XhttpConfig` 的 `sessionIDTable` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3629) |
| `sessionIDLength` | `XhttpRange（可选）` | 可选；默认不设置 | `sessionIdLength`<br>`session-length`<br>`session-id-length`<br>`session_id_length` | 无 | `XhttpConfig` 的 `sessionIDLength` 参数。解析类型为 `XhttpRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3639) |
| `seqPlacement` | `字符串（可选）` | 可选；默认不设置 | `seq-placement`<br>`seq_placement` | 无 | `XhttpConfig` 的 `seqPlacement` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3647) |
| `seqKey` | `字符串（可选）` | 可选；默认不设置 | `seq-key`<br>`seq_key` | 无 | `XhttpConfig` 的 `seqKey` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3655) |
| `uplinkDataPlacement` | `字符串（可选）` | 可选；默认不设置 | `uplink-data-placement`<br>`uplink_data_placement` | 无 | `XhttpConfig` 的 `uplinkDataPlacement` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3663) |
| `uplinkDataKey` | `字符串（可选）` | 可选；默认不设置 | `uplink-data-key`<br>`uplink_data_key` | 无 | `XhttpConfig` 的 `uplinkDataKey` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3671) |
| `uplinkChunkSize` | `XhttpRange（可选）` | 可选；默认不设置 | `uplink-chunk-size`<br>`uplink_chunk_size` | 无 | `XhttpConfig` 的 `uplinkChunkSize` 参数。解析类型为 `XhttpRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3679) |
| `noGRPCHeader` | `布尔值（可选）` | 可选；默认不设置 | `noGrpcHeader`<br>`no-grpc-header`<br>`no_grpc_header` | 无 | `XhttpConfig` 的 `noGRPCHeader` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3688) |
| `noSSEHeader` | `布尔值（可选）` | 可选；默认不设置 | `noSseHeader`<br>`no-sse-header`<br>`no_sse_header` | 无 | `XhttpConfig` 的 `noSSEHeader` 参数。解析类型为 `布尔值（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3697) |
| `scMaxEachPostBytes` | `XhttpRange（可选）` | 可选；默认不设置 | `sc-max-each-post-bytes`<br>`sc_max_each_post_bytes` | 无 | `XhttpConfig` 的 `scMaxEachPostBytes` 参数。解析类型为 `XhttpRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3705) |
| `scMinPostsIntervalMs` | `XhttpRange（可选）` | 可选；默认不设置 | `sc-min-posts-interval-ms`<br>`sc_min_posts_interval_ms` | 无 | `XhttpConfig` 的 `scMinPostsIntervalMs` 参数。解析类型为 `XhttpRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3713) |
| `scMaxBufferedPosts` | `整数（可选）` | 可选；默认不设置 | `sc-max-buffered-posts`<br>`sc_max_buffered_posts` | 无 | `XhttpConfig` 的 `scMaxBufferedPosts` 参数。解析类型为 `整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3721) |
| `scStreamUpServerSecs` | `XhttpRange（可选）` | 可选；默认不设置 | `sc-stream-up-server-secs`<br>`sc_stream_up_server_secs` | 无 | `XhttpConfig` 的 `scStreamUpServerSecs` 参数。解析类型为 `XhttpRange（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3729) |
| `serverMaxHeaderBytes` | `整数（可选）` | 可选；默认不设置 | `server-max-header-bytes`<br>`server_max_header_bytes` | 无 | `XhttpConfig` 的 `serverMaxHeaderBytes` 参数。解析类型为 `整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3737) |
| `xmux` | `XhttpXmuxConfig（可选）` | 可选；默认不设置 | 无 | 无 | `XhttpConfig` 的 `xmux` 参数。解析类型为 `XhttpXmuxConfig（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3739) |
| `downloadSettings` | `XhttpDownloadSettings（可选）` | 可选；默认不设置 | `download-settings`<br>`downloadConfig`<br>`download-config`<br>`download_config` | 无 | `XhttpConfig` 的 `downloadSettings` 参数。解析类型为 `XhttpDownloadSettings（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3749) |
| `extra` | `XhttpConfig（可选）` | 可选；默认不设置 | 无 | 无 | Xray 的兼容覆盖块。它仍是强类型 SplitHTTPConfig，不是任意 JSON。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L3752) |

## 本分类枚举

### `XhttpListenSet`

`listen.xhttp` 的单项/数组兼容表示。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1078)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `One(XhttpListener)` | 无 | 映射到 Rust 变体 `XhttpListenSet::One`。 |
| `Many(Vec<XhttpListener>)` | 无 | 映射到 Rust 变体 `XhttpListenSet::Many`。 |

### `XhttpListenAlpn`

规范序列化值与 TLS ALPN wire name 保持一致。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1265)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `http/1.1` | `h1`<br>`http1` | 映射到 Rust 变体 `XhttpListenAlpn::Http1`。 |
| `h2` | `http/2` | 映射到 Rust 变体 `XhttpListenAlpn::H2`。 |
| `h3` | `http/3` | 映射到 Rust 变体 `XhttpListenAlpn::H3`。 |

### `XhttpRealityTarget`

`XhttpRealityTarget` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2094)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Port(u16)` | 无 | 映射到 Rust 变体 `XhttpRealityTarget::Port`。 |
| `Address(String)` | 无 | 映射到 Rust 变体 `XhttpRealityTarget::Address`。 |

### `XhttpTcpFastOpen`

`XhttpTcpFastOpen` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2101)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Enabled(bool)` | 无 | 映射到 Rust 变体 `XhttpTcpFastOpen::Enabled`。 |
| `QueueLength(i32)` | 无 | 映射到 Rust 变体 `XhttpTcpFastOpen::QueueLength`。 |

### `XhttpTlsCertificateUsage`

`XhttpTlsCertificateUsage` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2107)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `encipherment` | 无 | 映射到 Rust 变体 `XhttpTlsCertificateUsage::Encipherment`。 |
| `verify` | 无 | 映射到 Rust 变体 `XhttpTlsCertificateUsage::Verify`。 |
| `issue` | 无 | 映射到 Rust 变体 `XhttpTlsCertificateUsage::Issue`。 |

### `XhttpTproxyMode`

`XhttpTproxyMode` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2196)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `off` | 无 | 映射到 Rust 变体 `XhttpTproxyMode::Off`。 |
| `tproxy` | 无 | 映射到 Rust 变体 `XhttpTproxyMode::Tproxy`。 |
| `redirect` | 无 | 映射到 Rust 变体 `XhttpTproxyMode::Redirect`。 |

### `XhttpDomainStrategy`

`XhttpDomainStrategy` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2206)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `AsIs` | `asis` | 映射到 Rust 变体 `XhttpDomainStrategy::AsIs`。 |
| `UseIP` | `useip` | 映射到 Rust 变体 `XhttpDomainStrategy::UseIp`。 |
| `UseIPv4` | `useipv4` | 映射到 Rust 变体 `XhttpDomainStrategy::UseIpv4`。 |
| `UseIPv6` | `useipv6` | 映射到 Rust 变体 `XhttpDomainStrategy::UseIpv6`。 |
| `UseIPv4v6` | `useipv4v6` | 映射到 Rust 变体 `XhttpDomainStrategy::UseIpv4v6`。 |
| `UseIPv6v4` | `useipv6v4` | 映射到 Rust 变体 `XhttpDomainStrategy::UseIpv6v4`。 |
| `ForceIP` | `forceip` | 映射到 Rust 变体 `XhttpDomainStrategy::ForceIp`。 |
| `ForceIPv4` | `forceipv4` | 映射到 Rust 变体 `XhttpDomainStrategy::ForceIpv4`。 |
| `ForceIPv6` | `forceipv6` | 映射到 Rust 变体 `XhttpDomainStrategy::ForceIpv6`。 |
| `ForceIPv4v6` | `forceipv4v6` | 映射到 Rust 变体 `XhttpDomainStrategy::ForceIpv4v6`。 |
| `ForceIPv6v4` | `forceipv6v4` | 映射到 Rust 变体 `XhttpDomainStrategy::ForceIpv6v4`。 |

### `XhttpAddressPortStrategy`

`XhttpAddressPortStrategy` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2232)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `none` | 无 | 映射到 Rust 变体 `XhttpAddressPortStrategy::None`。 |
| `srvPortOnly` | `srvportonly` | 映射到 Rust 变体 `XhttpAddressPortStrategy::SrvPortOnly`。 |
| `srvAddressOnly` | `srvaddressonly` | 映射到 Rust 变体 `XhttpAddressPortStrategy::SrvAddressOnly`。 |
| `srvPortAndAddress` | `srvportandaddress` | 映射到 Rust 变体 `XhttpAddressPortStrategy::SrvPortAndAddress`。 |
| `txtPortOnly` | `txtportonly` | 映射到 Rust 变体 `XhttpAddressPortStrategy::TxtPortOnly`。 |
| `txtAddressOnly` | `txtaddressonly` | 映射到 Rust 变体 `XhttpAddressPortStrategy::TxtAddressOnly`。 |
| `txtPortAndAddress` | `txtportandaddress` | 映射到 Rust 变体 `XhttpAddressPortStrategy::TxtPortAndAddress`。 |

### `XhttpMaskPacketEncoding`

`XhttpMaskPacketEncoding` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2250)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `array` | 无 | 映射到 Rust 变体 `XhttpMaskPacketEncoding::Array`。 |
| `str` | 无 | 映射到 Rust 变体 `XhttpMaskPacketEncoding::String`。 |
| `hex` | 无 | 映射到 Rust 变体 `XhttpMaskPacketEncoding::Hex`。 |
| `base64` | 无 | 映射到 Rust 变体 `XhttpMaskPacketEncoding::Base64`。 |

### `XhttpMaskPacket`

`XhttpMaskPacket` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2263)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Bytes(Vec<u8>)` | 无 | 映射到 Rust 变体 `XhttpMaskPacket::Bytes`。 |
| `Text(String)` | 无 | 映射到 Rust 变体 `XhttpMaskPacket::Text`。 |

### `XhttpMaskDomain`

`XhttpMaskDomain` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2270)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `One(String)` | 无 | 映射到 Rust 变体 `XhttpMaskDomain::One`。 |
| `Many(Vec<String>)` | 无 | 映射到 Rust 变体 `XhttpMaskDomain::Many`。 |

### `XhttpPortList`

`XhttpPortList` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2277)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `One(u16)` | 无 | 映射到 Rust 变体 `XhttpPortList::One`。 |
| `List(String)` | 无 | 映射到 Rust 变体 `XhttpPortList::List`。 |

### `XhttpTcpMask`

`XhttpTcpMask` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2407)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `header-custom{ #[serde(default)] settings: XhttpHeaderCustomTcp, }` | 无 | 映射到 Rust 变体 `XhttpTcpMask::HeaderCustom`。 |
| `fragment{ #[serde(default)] settings: XhttpFragmentMask, }` | 无 | 映射到 Rust 变体 `XhttpTcpMask::Fragment`。 |
| `sudoku{ #[serde(default)] settings: XhttpSudokuMask, }` | 无 | 映射到 Rust 变体 `XhttpTcpMask::Sudoku`。 |
| `xmc{ #[serde(default)] settings: XhttpXmcMask, }` | 无 | 映射到 Rust 变体 `XhttpTcpMask::Xmc`。 |

### `XhttpUdpMask`

`XhttpUdpMask` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L2539)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `header-custom{ #[serde(default)] settings: XhttpHeaderCustomUdp, }` | 无 | 映射到 Rust 变体 `XhttpUdpMask::HeaderCustom`。 |
| `mkcp-legacy{ #[serde(default)] settings: XhttpMkcpLegacyMask, }` | 无 | 映射到 Rust 变体 `XhttpUdpMask::MkcpLegacy`。 |
| `noise{ #[serde(default)] settings: XhttpNoiseMask, }` | 无 | 映射到 Rust 变体 `XhttpUdpMask::Noise`。 |
| `salamander{ #[serde(default)] settings: XhttpSalamanderMask, }` | 无 | 映射到 Rust 变体 `XhttpUdpMask::Salamander`。 |
| `sudoku{ #[serde(default)] settings: XhttpSudokuMask, }` | 无 | 映射到 Rust 变体 `XhttpUdpMask::Sudoku`。 |
| `xdns{ #[serde(default)] settings: XhttpXdnsMask, }` | 无 | 映射到 Rust 变体 `XhttpUdpMask::Xdns`。 |
| `xicmp{ #[serde(default)] settings: XhttpXicmpMask, }` | 无 | 映射到 Rust 变体 `XhttpUdpMask::Xicmp`。 |
| `realm{ #[serde(default)] settings: XhttpRealmMask, }` | 无 | 映射到 Rust 变体 `XhttpUdpMask::Realm`。 |
