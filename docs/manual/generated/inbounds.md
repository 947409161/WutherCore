---
title: 监听与服务端入站 完整字段索引
hide:
  - feedback
---

# 监听与服务端入站 完整字段索引

!!! info "由配置源码生成"

    本页由 `scripts/config-reference.py` 从 `core-config` 的公开 Serde
    结构生成，覆盖 YAML/JSON 实际接受的字段、重命名、别名、默认规则和
    枚举写法。修改配置模型后必须重新生成；CI 会拒绝缺字段或过期页面。

Mixed、Panel、Shadowsocks、WireGuard、Young、gRPC、REALITY 和 XHTTP 入站。

全手册当前覆盖 **744 个字段**、**53 个枚举类型**。
行为说明和跨字段约束请同时阅读同分类下的人工手册页面。

## `Listen`

`Listen` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L207)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `local` | `ListenLocal（可选）` | 可选；默认不设置 | 无 | `Port(u16)`<br>`Detail(ListenLocalDetail)` | `Listen` 的 `local` 参数。解析类型为 `ListenLocal（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L209) |
| `panel` | `PanelBind（可选）` | 可选；默认不设置 | 无 | `Off(bool)`<br>`Port(u16)`<br>`Address(String)` | `Listen` 的 `panel` 参数。解析类型为 `PanelBind（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L211) |
| `xhttp` | `XhttpListenSet（可选）` | 可选；默认不设置 | `split-http`<br>`split_http`<br>`splithttp` | 无 | XHTTP/SplitHTTP 服务端监听。既接受单个对象，也接受对象数组。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L219) |
| `shadowsocks` | `ShadowsocksListenSet（可选）` | 可选；默认不设置 | `ss` | `One(ShadowsocksListen)`<br>`Many(Vec<ShadowsocksListen>)` | Shadowsocks SIP003/SIP004/SIP022 服务端监听。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L222) |
| `share` | `Share（可选）` | 可选；默认不设置 | 无 | `false`<br>`home`<br>`all` | `Listen` 的 `share` 参数。解析类型为 `Share（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L224) |
| `auth` | `字符串 列表` | 可选；默认空 | 无 | 无 | `Listen` 的 `auth` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L226) |
| `reality` | `RealityListen 列表` | 可选；默认空 | `reality-inbounds`<br>`reality_inbounds` | 无 | REALITY 是一层入站流安全协议；每个条目独立监听并在认证后交给 `protocol` 指定的内层代理协议。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L230) |
| `wireguard` | `WireGuardListen 列表` | 可选；默认空 | `wireguard-inbounds`<br>`wireguard_inbounds` | 无 | WireGuard 服务端入站。每个条目绑定一个 UDP 端口，并把已认证对端的 IPv4/IPv6 包交给 WutherCore 的 TCP/UDP 路由运行时。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L234) |
| `young` | `YoungListen 列表` | 可选；默认空 | `young-inbounds`<br>`young_inbounds` | 无 | Young 原生入站。传输层是 Firefox 使用的 Mozilla Neqo HTTP/3/WebTransport。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L237) |
| `grpc` | `GrpcListen 列表` | 可选；默认空 | `grpc-inbounds`<br>`grpc_inbounds` | 无 | Xray gRPC (`gun`) 入站。每个条目独立监听，并把 Tun/TunMulti 双向流交给 `protocol` 指定的内层代理协议。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L241) |

## `ShadowsocksListen`

`ShadowsocksListen` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L262)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `enabled` | `布尔值` | 可选；默认 `true` | 无 | 无 | 控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L264) |
| `address` | `字符串` | 可选；默认 `0.0.0.0` | `host` | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L266) |
| `port` | `0-65535 整数` | 必填 | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L267) |
| `method` | `字符串` | 必填 | 无 | 无 | `ShadowsocksListen` 的 `method` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L268) |
| `password` | `字符串` | 必填 | 无 | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L269) |
| `mode` | `字符串` | 可选；默认 `tcp_and_udp` | 无 | 无 | `ShadowsocksListen` 的 `mode` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L271) |
| `plugin` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | SIP003 服务端插件可执行文件。插件监听公开地址，Shadowsocks 服务端本身只监听插件分配的回环地址。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L275) |
| `plugin-opts` | `字符串（可选）` | 可选；默认不设置 | `plugin_opts` | 无 | `ShadowsocksListen` 的 `plugin-opts` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L277) |
| `plugin-args` | `字符串 列表` | 可选；默认空 | `plugin_args` | 无 | `ShadowsocksListen` 的 `plugin-args` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L279) |
| `plugin-mode` | `字符串（可选）` | 可选；默认不设置 | `plugin_mode` | 无 | `ShadowsocksListen` 的 `plugin-mode` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L281) |
| `plugin-startup-timeout` | `时长` | 可选；默认 `10s` | `plugin_startup_timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L288) |
| `users` | `ShadowsocksUser 列表` | 可选；默认空 | 无 | 无 | `ShadowsocksListen` 的 `users` 参数。解析类型为 `ShadowsocksUser 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L290) |
| `handshake-timeout` | `时长` | 可选；默认 `10s` | `handshake_timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L297) |
| `udp-timeout` | `时长` | 可选；默认 `5m` | `udp_timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L304) |
| `max-connections` | `非负整数` | 可选；默认 `1024` | `max_connections` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L310) |
| `max-udp-associations` | `非负整数` | 可选；默认 `4096` | `max_udp_associations` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L316) |
| `tag` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | 用于显示、日志和其它配置项引用的稳定名称。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L318) |

## `ShadowsocksUser`

`ShadowsocksUser` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L323)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `name` | `字符串` | 必填 | 无 | 无 | 用于显示、日志和其它配置项引用的稳定名称。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L324) |
| `key` | `字符串` | 必填 | 无 | 无 | `ShadowsocksUser` 的 `key` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L325) |

## `WireGuardListen`

`WireGuardListen` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L371)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `host` | `字符串` | 可选；默认 `0.0.0.0` | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L373) |
| `port` | `0-65535 整数` | 必填 | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L374) |
| `privateKey` | `字符串` | 必填 | `private_key`<br>`private-key` | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L376) |
| `peers` | `WireGuardListenPeer 列表` | 必填 | 无 | 无 | `WireGuardListen` 的 `peers` 参数。解析类型为 `WireGuardListenPeer 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L377) |
| `mtu` | `非负整数` | 可选；默认 `1420` | 无 | 无 | `WireGuardListen` 的 `mtu` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L379) |
| `packetQueue` | `非负整数` | 可选；默认 `1024` | `packet_queue`<br>`packet-queue` | 无 | `WireGuardListen` 的 `packetQueue` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L386) |
| `handshakeRateLimit` | `非负整数` | 可选；默认 `100` | `handshake_rate_limit`<br>`handshake-rate-limit` | 无 | `WireGuardListen` 的 `handshakeRateLimit` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L393) |

## `WireGuardListenPeer`

`WireGuardListenPeer` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L413)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `publicKey` | `字符串` | 必填 | `public_key`<br>`public-key` | 无 | `WireGuardListenPeer` 的 `publicKey` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L415) |
| `presharedKey` | `字符串（可选）` | 可选；默认不设置 | `preshared_key`<br>`preshared-key` | 无 | `WireGuardListenPeer` 的 `presharedKey` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L422) |
| `allowedIPs` | `字符串 列表` | 必填 | `allowed_ips`<br>`allowed-ips` | 无 | `WireGuardListenPeer` 的 `allowedIPs` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L424) |
| `reserved` | `0-255 整数 列表` | 可选；默认空 | 无 | 无 | `WireGuardListenPeer` 的 `reserved` 参数。解析类型为 `0-255 整数 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L426) |
| `persistentKeepalive` | `0-65535 整数（可选）` | 可选；默认不设置 | `persistent_keepalive`<br>`persistent-keepalive` | 无 | `WireGuardListenPeer` 的 `persistentKeepalive` 参数。解析类型为 `0-65535 整数（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L433) |

## `YoungListen`

`YoungListen` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L454)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `host` | `字符串` | 可选；默认 `0.0.0.0` | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L456) |
| `port` | `0-65535 整数` | 必填 | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L457) |
| `nssDatabase` | `字符串` | 必填 | `nss_database`<br>`nss-database`<br>`nss-db` | 无 | `YoungListen` 的 `nssDatabase` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L464) |
| `certificateNickname` | `字符串` | 必填 | `certificate_nickname`<br>`certificate-nickname`<br>`certificate` | 无 | `YoungListen` 的 `certificateNickname` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L471) |
| `authority` | `字符串` | 必填 | 无 | 无 | `YoungListen` 的 `authority` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L472) |
| `path` | `字符串` | 可选；默认 `/assets` | 无 | 无 | 文件或 URL 路径；相对路径按运行进程的工作目录解析。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L474) |
| `users` | `字符串 列表` | 可选；默认空 | 无 | 无 | `YoungListen` 的 `users` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L476) |
| `clockSkew` | `时长` | 可选；默认 `2m` | `clock_skew`<br>`clock-skew` | 无 | `YoungListen` 的 `clockSkew` 参数。解析类型为 `时长`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L484) |
| `idleTimeout` | `时长` | 可选；默认 `5m` | `idle_timeout`<br>`idle-timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L492) |
| `maxStreams` | `非负整数` | 可选；默认 `1024` | `max_streams`<br>`max-streams` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L499) |
| `maxSessions` | `非负整数` | 可选；默认 `4096` | `max_sessions`<br>`max-sessions` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L506) |
| `maxFlowsPerSession` | `非负整数` | 可选；默认 `1024` | `max_flows_per_session`<br>`max-flows-per-session` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L513) |
| `paddingMin` | `0-65535 整数` | 可选；默认 `d_e_f_a_u_l_t__p_a_d_d_i_n_g__m_i_n` | `padding_min`<br>`padding-min` | 无 | `YoungListen` 的 `paddingMin` 参数。解析类型为 `0-65535 整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L520) |
| `paddingMax` | `0-65535 整数` | 可选；默认 `d_e_f_a_u_l_t__p_a_d_d_i_n_g__m_a_x` | `padding_max`<br>`padding-max` | 无 | `YoungListen` 的 `paddingMax` 参数。解析类型为 `0-65535 整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L527) |
| `paddingSchemeLength` | `0-65535 整数` | 可选；默认 `d_e_f_a_u_l_t__p_a_d_d_i_n_g__s_c_h_e_m_e__l_e_n_g_t_h` | `padding_scheme_length`<br>`padding-scheme-length` | 无 | `YoungListen` 的 `paddingSchemeLength` 参数。解析类型为 `0-65535 整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L534) |
| `decoyStatus` | `0-65535 整数` | 可选；默认 `404` | `decoy_status`<br>`decoy-status` | 无 | `YoungListen` 的 `decoyStatus` 参数。解析类型为 `0-65535 整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L541) |
| `decoyBody` | `字符串` | 可选；默认 `<!doctype html><html><head><title>Not Found</title></head><body><h1>Not Found</h1></body></html>` | `decoy_body`<br>`decoy-body` | 无 | `YoungListen` 的 `decoyBody` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L548) |

## `GrpcListen`

`GrpcListen` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L578)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `host` | `字符串` | 可选；默认 `0.0.0.0` | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L580) |
| `port` | `0-65535 整数` | 必填 | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L581) |
| `protocol` | `字符串` | 可选；默认 `vless` | 无 | 无 | `GrpcListen` 的 `protocol` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L583) |
| `users` | `字符串 列表` | 可选；默认空 | 无 | 无 | `GrpcListen` 的 `users` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L585) |
| `grpcSettings` | `GrpcTransportSettings` | 可选；使用类型默认值 | `grpc`<br>`grpc_settings`<br>`grpc-settings` | 无 | `GrpcListen` 的 `grpcSettings` 参数。解析类型为 `GrpcTransportSettings`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L593) |
| `security` | `GrpcListenSecurity` | 可选；默认 `None` | 无 | `none（默认）`<br>`tls`<br>`reality` | 底层安全载波。省略时是明文 h2c；TLS 与 REALITY 必须显式选择， 防止密钥配置存在但因拼写或遗漏而静默降级。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L597) |
| `tlsSettings` | `XhttpDownloadTlsSettings（可选）` | 可选；默认不设置 | `tls_settings`<br>`tls-settings` | 无 | 与 Xray `tlsSettings` 同构的完整 TLS 对象。gRPC 会强制协商 h2， 其余证书、ECH、mTLS、版本、密码套件与曲线字段不做裁剪。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L606) |
| `requireClientCertificate` | `布尔值` | 可选；默认 `false` | `require_client_certificate`<br>`require-client-certificate` | 无 | `GrpcListen` 的 `requireClientCertificate` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L613) |
| `realitySettings` | `RealityListen（可选）` | 可选；默认不设置 | `reality_settings`<br>`reality-settings` | 无 | REALITY 服务端设置复用完整的监听模型。嵌套对象的 host、port、 protocol 与 users 由外层 gRPC 监听统一覆盖，避免重复配置冲突。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L622) |
| `handshakeTimeout` | `时长` | 可选；默认 `10s` | `handshake_timeout`<br>`handshake-timeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L630) |
| `maxMuxSessions` | `非负整数` | 可选；默认 `1024` | `max_mux_sessions`<br>`max-mux-sessions` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L637) |
| `maxConnections` | `非负整数` | 可选；默认 `4096` | `max_connections`<br>`max-connections` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L644) |
| `maxConcurrentStreams` | `非负整数` | 可选；默认 `1024` | `max_concurrent_streams`<br>`max-concurrent-streams` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L651) |
| `maxHeaderListSize` | `非负整数` | 可选；默认 `65536` | `max_header_list_size`<br>`max-header-list-size` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L658) |
| `trustedXForwardedFor` | `字符串 列表` | 可选；默认空 | `trusted_x_forwarded_for`<br>`trusted-x-forwarded-for` | 无 | 与 Xray 一致：这里存放“信任标记请求头”的名称；仅当请求中至少 存在一个标记头时，才采用 X-Forwarded-For 的第一个地址。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L667) |

## `RealityListen`

Xray REALITY 服务端监听配置。 字段名同时接受 Xray 的 camelCase 与本项目常用的 snake/kebab 写法； 未知字段一律拒绝，避免把密钥或限速字段拼错后静默降级。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L702)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `host` | `字符串` | 可选；默认 `0.0.0.0` | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L704) |
| `port` | `0-65535 整数` | 可选；默认 `0` | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L706) |
| `protocol` | `字符串` | 可选；默认 `vless` | 无 | 无 | `RealityListen` 的 `protocol` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L708) |
| `users` | `字符串 列表` | 可选；默认空 | 无 | 无 | `RealityListen` 的 `users` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L710) |
| `target` | `RealityTarget（可选）` | 可选；默认不设置 | 无 | `Port(u16)`<br>`Address(String)` | `RealityListen` 的 `target` 参数。解析类型为 `RealityTarget（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L712) |
| `dest` | `RealityTarget（可选）` | 可选；默认不设置 | 无 | `Port(u16)`<br>`Address(String)` | `RealityListen` 的 `dest` 参数。解析类型为 `RealityTarget（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L714) |
| `type` | `字符串（可选）` | 可选；默认不设置 | `target_type`<br>`target-type` | 无 | `RealityListen` 的 `type` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L716) |
| `show` | `布尔值` | 可选；默认 `false` | 无 | 无 | `RealityListen` 的 `show` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L718) |
| `masterKeyLog` | `字符串（可选）` | 可选；默认不设置 | `master_key_log`<br>`master-key-log` | 无 | `RealityListen` 的 `masterKeyLog` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L725) |
| `xver` | `0-255 整数` | 可选；默认 `0` | 无 | 无 | `RealityListen` 的 `xver` 参数。解析类型为 `0-255 整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L727) |
| `serverNames` | `字符串 列表` | 可选；默认空 | `server_names`<br>`server-names` | 无 | `RealityListen` 的 `serverNames` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L734) |
| `privateKey` | `字符串` | 可选；默认空字符串 | `private_key`<br>`private-key` | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L741) |
| `minClientVer` | `字符串（可选）` | 可选；默认不设置 | `min_client_ver`<br>`min-client-ver` | 无 | 对应范围或资源量的下限。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L748) |
| `maxClientVer` | `字符串（可选）` | 可选；默认不设置 | `max_client_ver`<br>`max-client-ver` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L755) |
| `maxTimeDiff` | `非负整数` | 可选；默认 `0` | `max_time_diff`<br>`max-time-diff` | 无 | 与 Xray 一致，单位为毫秒；0 表示不限制时钟差。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L763) |
| `shortIds` | `字符串 列表` | 可选；默认空 | `short_ids`<br>`short-ids` | 无 | `RealityListen` 的 `shortIds` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L765) |
| `mldsa65Seed` | `字符串（可选）` | 可选；默认不设置 | `mldsa65_seed`<br>`mldsa65-seed` | 无 | `RealityListen` 的 `mldsa65Seed` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L772) |
| `limitFallbackUpload` | `RealityFallbackLimit` | 可选；使用类型默认值 | `limit_fallback_upload`<br>`limit-fallback-upload` | 无 | `RealityListen` 的 `limitFallbackUpload` 参数。解析类型为 `RealityFallbackLimit`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L779) |
| `limitFallbackDownload` | `RealityFallbackLimit` | 可选；使用类型默认值 | `limit_fallback_download`<br>`limit-fallback-download` | 无 | `RealityListen` 的 `limitFallbackDownload` 参数。解析类型为 `RealityFallbackLimit`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L786) |
| `limits` | `RealityResourceLimits` | 可选；使用类型默认值 | 无 | 无 | `RealityListen` 的 `limits` 参数。解析类型为 `RealityResourceLimits`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L788) |
| `streamSettings` | `crate::NodeStreamSettings（可选）` | 可选；默认不设置 | `stream_settings` | 无 | Socket policy and TCP FinalMask applied before the REALITY ClientHello. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L791) |

## `RealityFallbackLimit`

`RealityFallbackLimit` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L844)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `afterBytes` | `非负整数` | 可选；默认 `0` | `after_bytes`<br>`after-bytes` | 无 | `RealityFallbackLimit` 的 `afterBytes` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L851) |
| `bytesPerSec` | `非负整数` | 可选；默认 `0` | `bytes_per_sec`<br>`bytes-per-sec` | 无 | `RealityFallbackLimit` 的 `bytesPerSec` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L858) |
| `burstBytesPerSec` | `非负整数` | 可选；默认 `0` | `burst_bytes_per_sec`<br>`burst-bytes-per-sec` | 无 | `RealityFallbackLimit` 的 `burstBytesPerSec` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L865) |

## `RealityResourceLimits`

`RealityResourceLimits` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L870)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `handshake_timeout` | `时长` | 可选；默认 `10s` | `handshake-timeout`<br>`handshakeTimeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L877) |
| `target_handshake_timeout` | `时长` | 可选；默认 `5s` | `target-handshake-timeout`<br>`targetHandshakeTimeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L884) |
| `idle_timeout` | `时长` | 可选；默认 `5m` | `idle-timeout`<br>`idleTimeout` | 无 | 超时上限；时长字段接受 `ms`、`s`、`m`、`h` 等 humantime 写法。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L891) |
| `max_client_hello_records` | `非负整数` | 可选；默认 `16` | `max-client-hello-records`<br>`maxClientHelloRecords` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L897) |
| `max_client_hello_record_payload` | `非负整数` | 可选；默认 `16640` | `max-client-hello-record-payload`<br>`maxClientHelloRecordPayload` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L903) |
| `max_client_hello_bytes` | `非负整数` | 可选；默认 `u16::MAX as usize` | `max-client-hello-bytes`<br>`maxClientHelloBytes` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L909) |
| `max_client_hello_wire_bytes` | `非负整数` | 可选；默认 `98304` | `max-client-hello-wire-bytes`<br>`maxClientHelloWireBytes` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L915) |
| `max_target_records` | `非负整数` | 可选；默认 `12` | `max-target-records`<br>`maxTargetRecords` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L921) |
| `max_target_handshake_bytes` | `非负整数` | 可选；默认 `98304` | `max-target-handshake-bytes`<br>`maxTargetHandshakeBytes` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L927) |
| `application_buffer_bytes` | `非负整数` | 可选；默认 `262144` | `application-buffer-bytes`<br>`applicationBufferBytes` | 无 | `RealityResourceLimits` 的 `application_buffer_bytes` 参数。解析类型为 `非负整数`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L933) |
| `max_concurrent_handshakes` | `非负整数` | 可选；默认 `1024` | `max-concurrent-handshakes`<br>`maxConcurrentHandshakes` | 无 | 对应资源或并发量的硬上限，用于限制内存、连接或任务扩张。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L939) |

## `ListenLocalDetail`

`ListenLocalDetail` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L970)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `host` | `字符串` | 可选；默认 `127.0.0.1` | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L972) |
| `port` | `0-65535 整数` | 必填 | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L973) |
| `auth` | `字符串 列表` | 可选；默认空 | 无 | 无 | `ListenLocalDetail` 的 `auth` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L975) |
| `udp` | `布尔值` | 可选；默认 `true` | 无 | 无 | `ListenLocalDetail` 的 `udp` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L977) |
| `streamSettings` | `crate::NodeStreamSettings（可选）` | 可选；默认不设置 | `stream_settings` | 无 | Xray-compatible listener socket policy and server-side final masks. Both spellings are accepted so native YAML and imported Xray objects share one typed configuration path. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L982) |

## 本分类枚举

### `ShadowsocksListenSet`

`ShadowsocksListenSet` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L246)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `One(ShadowsocksListen)` | 无 | 映射到 Rust 变体 `ShadowsocksListenSet::One`。 |
| `Many(Vec<ShadowsocksListen>)` | 无 | 映射到 Rust 变体 `ShadowsocksListenSet::Many`。 |

### `GrpcListenSecurity`

完整的 Xray gRPC 服务端监听配置。 `grpcSettings` 沿用 Xray 字段名；本地资源上限单独注册，所有未知字段 均拒绝，避免拼写错误导致无界队列或静默使用默认值。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L362)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `none（默认）` | 无 | 映射到 Rust 变体 `GrpcListenSecurity::None`。 |
| `tls` | 无 | 映射到 Rust 变体 `GrpcListenSecurity::Tls`。 |
| `reality` | 无 | 映射到 Rust 变体 `GrpcListenSecurity::Reality`。 |

### `RealityTarget`

`RealityTarget` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L828)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Port(u16)` | 无 | 映射到 Rust 变体 `RealityTarget::Port`。 |
| `Address(String)` | 无 | 映射到 Rust 变体 `RealityTarget::Address`。 |

### `ListenLocal`

listen.local 支持端口写法 / 完整对象。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L963)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Port(u16)` | 无 | 映射到 Rust 变体 `ListenLocal::Port`。 |
| `Detail(ListenLocalDetail)` | 无 | 映射到 Rust 变体 `ListenLocal::Detail`。 |

### `PanelBind`

`PanelBind` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1196)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Off(bool)` | 无 | 映射到 Rust 变体 `PanelBind::Off`。 |
| `Port(u16)` | 无 | 映射到 Rust 变体 `PanelBind::Port`。 |
| `Address(String)` | 无 | 映射到 Rust 变体 `PanelBind::Address`。 |

### `Share`

`Share` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1204)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `false` | 无 | 映射到 Rust 变体 `Share::False`。 |
| `home` | 无 | 映射到 Rust 变体 `Share::Home`。 |
| `all` | 无 | 映射到 Rust 变体 `Share::All`。 |

### `ShareValue`

`ShareValue` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L1212)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `Bool(bool)` | 无 | 映射到 Rust 变体 `ShareValue::Bool`。 |
| `Tag(Share)` | 无 | 映射到 Rust 变体 `ShareValue::Tag`。 |
