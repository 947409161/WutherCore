---
title: 系统接管、Smart、UI 与 Mesh 完整字段索引
hide:
  - feedback
---

# 系统接管、Smart、UI 与 Mesh 完整字段索引

!!! info "由配置源码生成"

    本页由 `scripts/config-reference.py` 从 `core-config` 的公开 Serde
    结构生成，覆盖 YAML/JSON 实际接受的字段、重命名、别名、默认规则和
    枚举写法。修改配置模型后必须重新生成；CI 会拒绝缺字段或过期页面。

透明接管/TUN、平台过滤、智能选择、管理面板和 Tailscale 协同。

全手册当前覆盖 **802 个字段**、**55 个枚举类型**。
行为说明和跨字段约束请同时阅读同分类下的人工手册页面。

## `Capture`

Capture / TUN 入站：兼容 mihomo / sing-box 常用 `inbounds[type=tun]` 字段。 Friendly 字段（顶层）保留 WutherCore 简洁语义；`tun` 子字段对齐 sing-box JSON。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5242)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `tag` | `字符串` | 可选；默认 `tun-in` | 无 | 无 | Stable inbound tag exposed to route matching and connection metadata. [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5245) |
| `on` | `布尔值` | 可选；默认 `false` | 无 | 无 | 控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5247) |
| `method` | `CaptureMethod` | 可选；默认 `auto` | 无 | `auto`<br>`virtual_nic`<br>`tproxy`<br>`redirect` | `Capture` 的 `method` 参数。解析类型为 `CaptureMethod`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5249) |
| `traffic` | `CaptureTraffic` | 可选；默认 `system` | 无 | `system`<br>`lan`<br>`apps` | `Capture` 的 `traffic` 参数。解析类型为 `CaptureTraffic`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5251) |
| `resolver` | `CaptureResolver` | 可选；默认 `hijack` | 无 | `off`<br>`hijack` | `Capture` 的 `resolver` 参数。解析类型为 `CaptureResolver`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5253) |
| `stack` | `CaptureStack` | 可选；默认 `mixed` | 无 | `system`<br>`mixed`<br>`native`<br>`smoltcp`<br>`gvisor` | `Capture` 的 `stack` 参数。解析类型为 `CaptureStack`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5255) |
| `mtu` | `std::num::NonZeroU16（可选）` | 可选；默认 不设置 | 无 | 无 | `Capture` 的 `mtu` 参数。解析类型为 `std::num::NonZeroU16（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5257) |
| `offload` | `布尔值` | 可选；默认 `true` | 无 | 无 | `Capture` 的 `offload` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5259) |
| `exclude` | `CaptureExclude` | 可选；默认 `CaptureExclude::default()` | 无 | 无 | `Capture` 的 `exclude` 参数。解析类型为 `CaptureExclude`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5261) |
| `tun` | `TunInboundOptions` | 可选；默认 `TunInboundOptions::default()` | 无 | 无 | sing-box 兼容子配置（详见 <https://sing-box.sagernet.org/configuration/inbound/tun/>）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5264) |

## `CaptureExclude`

`CaptureExclude` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5342)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `cidr` | `字符串 列表` | 可选；默认空 | 无 | 无 | `CaptureExclude` 的 `cidr` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5345) |
| `process` | `字符串 列表` | 可选；默认空 | 无 | 无 | `CaptureExclude` 的 `process` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5348) |

## `TunInboundOptions`

sing-box `inbounds[type=tun]` 兼容字段映射：见 <https://sing-box.sagernet.org/configuration/inbound/tun/>

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5683)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `interface_name` | `字符串（可选）` | 可选；默认 不设置 | 无 | 无 | `interface_name`：优先级高于 WutherCore 默认 `rpktun0/utun7/WutherCoreTun`。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5686) |
| `address` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `address`：TUN 接口 v4 / v6 CIDR 列表（首条 v4 / 首条 v6 生效）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5690) |
| `inet6` | `布尔值` | 可选；默认 `true` | 无 | 无 | `inet6`：是否在 TUN 上启用 IPv6。关闭后不配 v6 地址 / 路由 / 规则 / listener。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5693) |
| `auto_route` | `布尔值` | 可选；默认 `true` | 无 | 无 | `auto_route`：自动写默认路由（0.0.0.0/0 + ::/0 → tun）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5698) |
| `iproute2_table_index` | `非负整数` | 可选；默认 `2022` | 无 | 无 | `iproute2_table_index`：Linux 自定义路由表 id（默认 2022）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5701) |
| `iproute2_rule_index` | `非负整数` | 可选；默认 `9000` | 无 | 无 | `iproute2_rule_index`：`ip rule` 优先级起始 id。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5704) |
| `auto_redirect` | `布尔值` | 可选；默认 `false` | 无 | 无 | `auto_redirect`：在 auto_route TUN 数据面上，为 TCP 注入 nftables NAT REDIRECT。当前安全契约只把本机 UDP 送入 TUN； ICMP/其他协议不新增导流 rule，继续按已有主路由策略处理。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5709) |
| `auto_redirect_input_mark` | `字符串（可选）` | 可选；默认 不设置 | 无 | 无 | `auto_redirect_input_mark`：保留的 mark/NFQUEUE 入站 mark；当前 Linux REDIRECT 安全子集不消费，显式配置会失败。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5713) |
| `auto_redirect_output_mark` | `字符串（可选）` | 可选；默认 不设置 | 无 | 无 | `auto_redirect_output_mark`：跳过 redirect chain 的 fwmark。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5716) |
| `auto_redirect_reset_mark` | `字符串（可选）` | 可选；默认 不设置 | 无 | 无 | `auto_redirect_reset_mark`：NFQUEUE 预匹配的连接 reset mark（保留字段）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5719) |
| `auto_redirect_nfqueue` | `0-65535 整数（可选）` | 可选；默认 不设置 | 无 | 无 | `auto_redirect_nfqueue`：NFQUEUE 预匹配队列编号（当前无消费者）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5722) |
| `auto_redirect_iproute2_fallback_rule_index` | `非负整数（可选）` | 可选；默认 不设置 | 无 | 无 | `auto_redirect_iproute2_fallback_rule_index`：fallback ip rule 优先级。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5725) |
| `strict_route` | `布尔值` | 可选；默认 `false` | 无 | 无 | `strict_route`：严格防泄漏；任何未接管流量被 drop。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5728) |
| `route_address` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `route_address`：仅这些 CIDR 走 TUN（白名单）。空 = 全部。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5732) |
| `route_exclude_address` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `route_exclude_address`：这些 CIDR 不走 TUN（黑名单）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5736) |
| `route_address_set` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `route_address_set`：白名单引用 ruleset（动态 IP 集）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5740) |
| `route_exclude_address_set` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `route_exclude_address_set`：黑名单引用 ruleset。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5744) |
| `endpoint_independent_nat` | `布尔值` | 可选；默认 `false` | `endpoint-independent-nat` | 无 | `endpoint_independent_nat`：全锥 NAT；UDP 打洞场景需开。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5749) |
| `udp_timeout` | `时长` | 可选；默认 `5m` | `udp-timeout` | 无 | `udp_timeout`：UDP NAT 老化（默认 5m）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5756) |
| `exclude_mptcp` | `布尔值` | 可选；默认 `false` | 无 | 无 | `exclude_mptcp`：透传 MPTCP 不接管。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5759) |
| `loopback_address` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `loopback_address`：哪些 IP 视为 loopback 不接管（如保留地址）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5763) |
| `include_interface` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `include_interface`：仅接管这些上行接口的流量。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5769) |
| `exclude_interface` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `exclude_interface`：排除这些接口。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5773) |
| `include_uid` | `非负整数 列表` | 可选；默认 空 | 无 | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5778) |
| `include_uid_range` | `字符串 列表` | 可选；默认 空 | 无 | 无 | 形如 `"1000:99999"`，闭区间。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5782) |
| `exclude_uid` | `非负整数 列表` | 可选；默认 空 | 无 | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5785) |
| `exclude_uid_range` | `字符串 列表` | 可选；默认 空 | 无 | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5788) |
| `include_gid` | `非负整数 列表` | 可选；默认 空 | 无 | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5793) |
| `include_gid_range` | `字符串 列表` | 可选；默认 空 | 无 | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5796) |
| `exclude_gid` | `非负整数 列表` | 可选；默认 空 | 无 | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5799) |
| `exclude_gid_range` | `字符串 列表` | 可选；默认 空 | 无 | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5802) |
| `include_android_user` | `非负整数 列表` | 可选；默认 空 | 无 | 无 | `include_android_user`：仅接管这些 Android user id 的流量（双开 / 工作资料）。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5808) |
| `include_package` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `include_package`：Android 包名白名单。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5812) |
| `exclude_package` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `exclude_package`：Android 包名黑名单。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5816) |
| `include_mac_address` | `字符串 列表` | 可选；默认 空 | 无 | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5821) |
| `exclude_mac_address` | `字符串 列表` | 可选；默认 空 | 无 | 无 | 包含/排除过滤条件；与同配置块其它过滤器的组合规则见对应语义手册。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5824) |
| `platform` | `TunPlatformOptions（可选）` | 可选；默认 不设置 | 无 | 无 | `platform.http_proxy`：iOS/Android 系统代理透传。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5829) |

## `TunPlatformOptions`

`TunPlatformOptions` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5878)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `http_proxy` | `TunHttpProxyOptions（可选）` | 可选；默认不设置 | 无 | 无 | `TunPlatformOptions` 的 `http_proxy` 参数。解析类型为 `TunHttpProxyOptions（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5880) |

## `TunHttpProxyOptions`

`TunHttpProxyOptions` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5885)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `enabled` | `布尔值` | 可选；默认 `false` | 无 | 无 | 控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5887) |
| `server` | `字符串` | 可选；默认空字符串 | 无 | 无 | 监听或连接使用的主机/IP 地址；是否允许域名由所在协议和校验阶段决定。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5889) |
| `server_port` | `0-65535 整数` | 可选；默认 `0` | 无 | 无 | 监听或连接使用的端口；`0` 是否允许由所在配置块校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5891) |
| `bypass_domain` | `字符串 列表` | 可选；默认空 | 无 | 无 | `TunHttpProxyOptions` 的 `bypass_domain` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5893) |
| `match_domain` | `字符串 列表` | 可选；默认空 | 无 | 无 | `TunHttpProxyOptions` 的 `match_domain` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5895) |

## `Smart`

`Smart` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5902)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `on` | `布尔值` | 可选；默认 `true` | 无 | 无 | 控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5904) |
| `goal` | `SmartGoal` | 可选；默认 `balanced` | 无 | `balanced`<br>`speed`<br>`stability`<br>`lowcost`<br>`privacy` | `Smart` 的 `goal` 参数。解析类型为 `SmartGoal`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5906) |
| `learn` | `时长` | 可选；默认 `14d` | 无 | 无 | `Smart` 的 `learn` 参数。解析类型为 `时长`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5908) |
| `sticky` | `SmartSticky` | 可选；默认 `site` | 无 | `off`<br>`site`<br>`session` | `Smart` 的 `sticky` 参数。解析类型为 `SmartSticky`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5910) |
| `explain` | `布尔值` | 可选；默认 `true` | 无 | 无 | `Smart` 的 `explain` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5912) |

## `Ui`

`Ui` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5949)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `on` | `布尔值` | 可选；默认 `true` | 无 | 无 | 控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5951) |
| `secret` | `字符串（可选）` | 可选；默认 不设置 | 无 | 无 | 敏感认证材料；不要写入公开仓库、日志或截图。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5953) |
| `dashboard` | `字符串` | 可选；默认 `auto` | 无 | 无 | `Ui` 的 `dashboard` 参数。解析类型为 `字符串`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5955) |
| `api` | `UiApi` | 可选；默认 `UiApi::default()` | 无 | 无 | `Ui` 的 `api` 参数。解析类型为 `UiApi`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5957) |
| `cors` | `字符串 列表` | 可选；默认 空 | 无 | 无 | `Ui` 的 `cors` 参数。解析类型为 `字符串 列表`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5959) |

## `UiApi`

`UiApi` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5976)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `native` | `布尔值` | 可选；默认 `true` | 无 | 无 | `UiApi` 的 `native` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5978) |
| `clash_compat` | `布尔值` | 可选；默认 `true` | 无 | 无 | `UiApi` 的 `clash_compat` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5980) |

## `Mesh`

`Mesh` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5996)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `tailscale` | `MeshTailscale（可选）` | 可选；默认不设置 | 无 | 无 | `Mesh` 的 `tailscale` 参数。解析类型为 `MeshTailscale（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5998) |

## `MeshTailscale`

`MeshTailscale` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L6003)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `on` | `布尔值` | 可选；默认 `true` | 无 | 无 | 控制该配置块是否启用；关闭时保留配置但不启动对应运行时能力。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L6005) |
| `mode` | `TailscaleMode` | 可选；默认 `auto` | 无 | `auto`<br>`localapi`<br>`userspace`<br>`tsnet`<br>`off` | `MeshTailscale` 的 `mode` 参数。解析类型为 `TailscaleMode`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L6007) |
| `keep_tailnet_direct` | `布尔值` | 可选；默认 `true` | 无 | 无 | `MeshTailscale` 的 `keep_tailnet_direct` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L6009) |
| `expose_as_node` | `布尔值` | 可选；默认 `false` | 无 | 无 | `MeshTailscale` 的 `expose_as_node` 参数。解析类型为 `布尔值`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L6011) |
| `userspace_proxy` | `TailscaleUserspaceProxy（可选）` | 可选；默认 不设置 | 无 | 无 | `MeshTailscale` 的 `userspace_proxy` 参数。解析类型为 `TailscaleUserspaceProxy（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L6013) |

## `TailscaleUserspaceProxy`

`TailscaleUserspaceProxy` 配置对象。

[查看权威源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L6039)

| YAML / JSON 字段 | 类型 | 必填与默认 | 兼容别名 | 取值 / 形态 | 解析与用途 |
| --- | --- | --- | --- | --- | --- |
| `socks` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `TailscaleUserspaceProxy` 的 `socks` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L6041) |
| `http` | `字符串（可选）` | 可选；默认不设置 | 无 | 无 | `TailscaleUserspaceProxy` 的 `http` 参数。解析类型为 `字符串（可选）`；组合约束由 `wuther-core check` 校验。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L6043) |

## 本分类枚举

### `CaptureMethod`

`CaptureMethod` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5290)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `auto` | 无 | 映射到 Rust 变体 `CaptureMethod::Auto`。 |
| `virtual_nic` | `tun` | 映射到 Rust 变体 `CaptureMethod::VirtualNic`。 |
| `tproxy` | 无 | 映射到 Rust 变体 `CaptureMethod::Tproxy`。 |
| `redirect` | 无 | 映射到 Rust 变体 `CaptureMethod::Redirect`。 |

### `CaptureTraffic`

`CaptureTraffic` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5300)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `system` | 无 | 映射到 Rust 变体 `CaptureTraffic::System`。 |
| `lan` | 无 | 映射到 Rust 变体 `CaptureTraffic::Lan`。 |
| `apps` | 无 | 映射到 Rust 变体 `CaptureTraffic::Apps`。 |

### `CaptureResolver`

`CaptureResolver` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5308)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `off` | `disabled` | 映射到 Rust 变体 `CaptureResolver::Off`。 |
| `hijack` | 无 | 映射到 Rust 变体 `CaptureResolver::Hijack`。 |

### `CaptureStack`

TCP/UDP 栈选择：对标 sing-tun `stack` 字段。 sing-tun 实现： - `system` = TCP 走 OS 内核 NAT + TcpListener accept，UDP 走 OS 转发 - `mixed` = TCP 同 system，UDP 走 gVisor 用户态 - `gvisor` = TCP + UDP 全部走 gVisor 用户态 WutherCore 映射： - `system` / `mixed` / `native` → SystemDispatcher（TCP NAT + OS accept + UDP forwarder） - `gvisor` / `smoltcp` → TunDispatcher（smoltcp 用户态 TCP，仅测试/备用） [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5326)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `system` | 无 | sing-tun `system` 栈：TCP NAT 改写 + OS TcpListener accept。 |
| `mixed` | 无 | sing-tun `mixed` 栈：TCP 同 system，UDP forwarder。推荐默认值。 |
| `native` | 无 | 等价 system（向后兼容旧配置）。 |
| `smoltcp` | 无 | smoltcp 用户态 TCP 栈（测试/备用）。 |
| `gvisor` | 无 | gVisor 占位（当前等价 smoltcp）。 |

### `SmartGoal`

`SmartGoal` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5929)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `balanced` | 无 | 映射到 Rust 变体 `SmartGoal::Balanced`。 |
| `speed` | 无 | 映射到 Rust 变体 `SmartGoal::Speed`。 |
| `stability` | 无 | 映射到 Rust 变体 `SmartGoal::Stability`。 |
| `lowcost` | 无 | 映射到 Rust 变体 `SmartGoal::LowCost`。 |
| `privacy` | 无 | 映射到 Rust 变体 `SmartGoal::Privacy`。 |

### `SmartSticky`

`SmartSticky` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L5939)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `off` | 无 | 映射到 Rust 变体 `SmartSticky::Off`。 |
| `site` | 无 | 映射到 Rust 变体 `SmartSticky::Site`。 |
| `session` | 无 | 映射到 Rust 变体 `SmartSticky::Session`。 |

### `TailscaleMode`

`TailscaleMode` 的可接受配置形态。 [源码](https://github.com/MiChongs/WutherCore/blob/main/crates/core-config/src/model.rs#L6030)

| 写法 | 兼容别名 | 含义 |
| --- | --- | --- |
| `auto` | 无 | 映射到 Rust 变体 `TailscaleMode::Auto`。 |
| `localapi` | 无 | 映射到 Rust 变体 `TailscaleMode::Localapi`。 |
| `userspace` | 无 | 映射到 Rust 变体 `TailscaleMode::Userspace`。 |
| `tsnet` | 无 | 映射到 Rust 变体 `TailscaleMode::Tsnet`。 |
| `off` | 无 | 映射到 Rust 变体 `TailscaleMode::Off`。 |
