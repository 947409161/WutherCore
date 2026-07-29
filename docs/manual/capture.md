---
title: 系统接管
description: TUN、TPROXY、REDIRECT 入口与平台差异的完整配置说明
---

# 系统接管

透明 `inbound` 决定哪些系统流量进入 WutherCore，以及进入后由哪种数据面处理。它涉及
操作系统权限、路由表、防火墙和 TUN 设备，配置成功不代表当前进程一定具备激活权限。
部署前应先运行 `wuther-core check`，再用与正式服务相同的用户启动。

`type` 可选 `tun`、`tproxy` 或 `redirect`。入口参数采用 sing-box 风格的扁平结构，
不再拆成 `capture` 与 `capture.tun` 两层。

## 顶层字段

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `type` | 必填 | 选择 `tun`、`tproxy` 或 `redirect` |
| `tag` | 按类型生成 | 路由、连接表、日志和 API 使用的稳定入口名称 |
| `enabled` | `true` | 是否启用该入口 |
| `traffic` | `system` | 接管本机、局域网或应用范围 |
| `dns_mode` | `hijack` | 是否劫持进入数据面的 DNS 请求 |
| `stack` | `mixed` | 选择 TCP 和 UDP 的协议栈实现 |
| `mtu` | 平台决定 | 覆盖 TUN 接口 MTU |
| `offload` | `true` | 在支持的数据面启用批处理或校验和卸载 |
| `exclude` | 空对象 | 按 CIDR 或进程排除流量 |

最小桌面配置：

```yaml
inbounds:
  - type: mixed
    tag: 本地代理
    listen_port: 7890
  - type: tun
    tag: 系统接管
    traffic: system
    dns_mode: hijack
    stack: mixed
    auto_route: true
```

只要显式写出 `inbounds`，Profile 就不会再创建旧式 Mixed 或透明接管默认值。
不写 `inbounds` 的旧配置仍按原 Profile 行为补全。

## 接管方法

| `type` | 适用场景 | 关键限制 |
| --- | --- | --- |
| `tun` | TUN 虚拟网卡 | 要求组件 `with_tun` |
| `tproxy` | Linux 或 Android root 透明代理 | 需要策略路由、防火墙权限和内核支持 |
| `redirect` | Linux 或 Android root TCP REDIRECT | UDP 需要其它数据面配合 |

`tun` 是跨平台配置入口，但设备创建方式不同。Linux 可以由进程创建和管理
设备。Android root daemon 优先直接打开 `/dev/net/tun`，打开失败后才使用宿主
注入的 VpnService 文件描述符。macOS 和 Windows 受系统扩展、签名、权限和宿主
集成约束。

Android 的 root TUN、TPROXY、REDIRECT、VpnService、权限边界和完整配置见
[Android 完整部署](android.md)。

## 流量范围

`traffic` 支持：

| 值 | 含义 |
| --- | --- |
| `system` | 接管本机产生的系统流量 |
| `lan` | 面向路由器转发的局域网流量 |
| `apps` | 面向 Android 等平台的应用选择 |

字段可被模型接受，不等于所有平台和方法都能执行。运行计划会根据方法、平台和过滤
字段组合再次校验。无法可靠实现的组合会失败，不会静默缩小接管范围。

## DNS 劫持

`dns_mode: hijack` 将进入接管数据面的 DNS 请求交给 WutherCore Resolver。
`dns_mode: off` 保留原有 DNS 路径。要避免循环：

1. Resolver 上游必须能通过选定出站访问。
2. 本地监听地址不能再次被 TUN 接管。
3. Fake IP 模式必须与路由和应用兼容。
4. 调试时先用 `dns_mode: off` 区分 DNS 问题和数据面问题。

Resolver 的服务器、策略、Fallback 和 Fake IP 配置见
[策略组、路由与 DNS](routing-dns.md)。

## 协议栈

| `stack` | 当前语义 | 建议 |
| --- | --- | --- |
| `mixed` | 系统 TCP 路径与 UDP 转发路径组合 | 默认选择 |
| `system` | 依赖操作系统 TCP NAT 和监听能力 | 适合成熟的平台接入 |
| `native` | `system` 的兼容写法 | 新配置使用 `system` |
| `smoltcp` | 用户态 TCP 实现 | 测试或特定平台备用 |
| `gvisor` | 当前映射到用户态备用路径 | 不应假定具备 sing-tun 的完整 gVisor 行为 |

## MTU 与 Offload

`mtu` 是非零 16 位整数。运行计划还执行语义校验：

- 可用范围为 `576` 到 `65535`。
- 开启 IPv6 时不得低于 `1280`。
- TPROXY 和 REDIRECT 不创建 TUN 接口，因此显式 `mtu` 没有意义并会被拒绝。
- 路径 MTU 问题通常表现为大包、TLS 握手或上传停滞，可先尝试 `1400` 或 `1280`。

`offload` 默认开启。平台不支持时，运行计划按数据面能力处理。排错时可以临时关闭，
用于判断问题是否来自批处理、GSO 或校验和卸载。

## 排除项

```yaml
inbounds:
  - type: tun
    tag: system-tun
    exclude:
      cidr:
        - 127.0.0.0/8
        - ::1/128
        - 192.168.0.0/16
      process:
        - wuther-core
```

`exclude.cidr` 使用 CIDR。`exclude.process` 使用平台进程查询结果，能力受操作系统、
权限和 `process-lookup` 设置影响。对内核进程、短生命周期进程或受保护应用，不应
把进程名过滤当成唯一的防回环机制。

## TUN 接口

### 接口与地址

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `interface_name` | 平台决定 | 覆盖自动生成的接口名 |
| `address` | 空列表 | IPv4 和 IPv6 CIDR，首个有效地址用于接口配置 |
| `inet6` | `true` | 是否启用 IPv6 地址、路由和监听 |
| `auto_route` | `true` | 自动安装接管路由 |
| `strict_route` | `false` | 拒绝未按计划进入代理路径的流量 |

地址示例：

```yaml
inbounds:
  - type: tun
    tag: system-tun
    interface_name: rpktun0
    address:
      - 172.19.0.1/30
      - fdfe:dcba:9876::1/126
    inet6: true
    auto_route: true
```

关闭 `inet6` 后，不应再配置依赖 IPv6 的地址和路由。`strict_route` 会改变失败时的
连通性，先在可恢复的会话中验证。

### 路由选择

| 字段组 | 字段 |
| --- | --- |
| Linux 表与规则 | `iproute2_table_index`、`iproute2_rule_index` |
| 静态接管白名单 | `route_address` |
| 静态绕行黑名单 | `route_exclude_address` |
| 动态规则集白名单 | `route_address_set` |
| 动态规则集黑名单 | `route_exclude_address_set` |
| 环回地址 | `loopback_address` |

`route_address` 为空表示不通过这个字段缩小范围。CIDR 白名单和黑名单同时存在时，
黑名单用于明确绕行。引用规则集前，规则集必须存在并且能提供该数据面要求的 IP
快照。某些 Linux `auto_redirect` 组合明确禁止动态集合。

### NAT 与 UDP

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `endpoint_independent_nat` | `false` | UDP 使用端点独立映射，兼容别名 `endpoint-independent-nat` |
| `udp_timeout` | `5m` | UDP NAT 状态老化时间，兼容别名 `udp-timeout` |
| `exclude_mptcp` | `false` | 排除 MPTCP 流量 |

端点独立 NAT 有利于部分实时通信和打洞场景，但会改变映射复用和安全边界。应按业务
需要开启，而不是作为通用性能开关。

### 接口、用户与应用过滤

| 范围 | 包含字段 | 排除字段 |
| --- | --- | --- |
| 上行接口 | `include_interface` | `exclude_interface` |
| Linux 或 Android UID | `include_uid`、`include_uid_range` | `exclude_uid`、`exclude_uid_range` |
| Linux 或 Android GID | `include_gid`、`include_gid_range` | `exclude_gid`、`exclude_gid_range` |
| Android 包名 | `include_package` | `exclude_package` |
| 局域网设备 MAC | `include_mac_address` | `exclude_mac_address` |

UID 和 GID 范围写成闭区间字符串，例如 `"1000:99999"`。
`include_android_user` 按 Android user id 限定多用户或工作资料空间。

同一维度同时配置包含和排除时，先由包含集合缩小候选范围，再应用排除集合。平台
没有可靠实现某字段时会在激活阶段拒绝，不应把字段被解析视为字段已生效。

### 平台 HTTP 代理

```yaml
inbounds:
  - type: tun
    tag: system-tun
    platform:
      http_proxy:
        enabled: true
        server: 127.0.0.1
        server_port: 7890
        bypass_domain:
          - localhost
        match_domain:
          - example.com
```

这组字段用于 iOS 或 Android 宿主向系统代理桥接。它不创建 WutherCore 的 Mixed
监听，`server` 和 `server_port` 必须指向实际可达的 HTTP 代理入口。

## Linux `auto_redirect`

`auto_redirect` 是 Linux root-managed TUN 的安全子集：

- TCP 通过 nftables NAT REDIRECT 进入临时监听。
- UDP 通过策略路由进入 TUN。
- ICMP 和其它协议不新增接管规则。
- `traffic` 必须为 `system`。
- `type` 必须为 `tun`。
- `auto_route` 必须开启，`strict_route` 必须关闭。

输出 mark 可以省略，省略或写 `0` 时使用 `0x2024`。当前实现拒绝显式 input mark、
reset mark、NFQUEUE、fallback rule index、动态路由集合及平台过滤字段，避免生成
看似成功但不完整的规则。

生产前必须阅读
[Linux TUN auto_redirect](../LINUX-TUN-AUTO-REDIRECT.md)，其中包含路由表所有权、
规则优先级、原子安装、回滚和故障恢复契约。

## 平台能力表

| 能力 | Linux | Android | macOS | Windows |
| --- | --- | --- | --- | --- |
| `tun` 配置模型 | 支持 | 支持 | 支持 | 支持 |
| 进程自行创建 TUN | 支持，需要权限 | root daemon 支持 `/dev/net/tun` | 取决于宿主集成 | 取决于宿主集成 |
| 非 root TUN | 不适用 | VpnService fd | 取决于宿主集成 | 取决于宿主集成 |
| 显式 TPROXY | 支持 | root daemon 支持 TCP 和 UDP | 不支持 | 不支持 |
| 显式 REDIRECT | 支持 TCP | root daemon 支持 TCP | 不支持 | 不支持 |
| `auto_redirect` 安全子集 | 支持 | 不支持 | 不支持 | 不支持 |
| UID/GID 过滤 | 支持部分数据面 | 支持部分数据面 | 不支持 | 不支持 |
| Android user 与包名 | 不支持 | root TUN 和 VpnService 支持，透明模式有单独限制 | 不支持 | 不支持 |
| `platform.http_proxy` | 无需使用 | 支持宿主桥接 | 支持宿主桥接 | 无需使用 |

该表描述配置入口，不替代运行时能力检查。最终结果以 `check`、`explain` 和启动日志
为准。

## 旧配置迁移

旧的 `capture` 仍可读取。迁移时按下面的规则展开：

| 旧字段 | 新字段 |
| --- | --- |
| `capture.on` | `inbounds[].enabled` |
| `capture.method: virtual_nic` | `inbounds[].type: tun` |
| `capture.method: tproxy` | `inbounds[].type: tproxy` |
| `capture.method: redirect` | `inbounds[].type: redirect` |
| `capture.resolver` | `inbounds[].dns_mode` |
| `capture.tun.*` | 直接放入同一个 `inbounds[]` 条目 |

新旧透明入口不能同时配置。`capture.method: auto` 没有直接对应的新值，迁移时应根据
目标平台明确选择 `tun`、`tproxy` 或 `redirect`。

## 验证顺序

```bash
wuther-core check config.yaml
wuther-core explain config.yaml
wuther-core run --config config.yaml
```

Linux 还应核对接口、路由和防火墙实际状态。任何安装步骤失败时，程序会尝试按所有权
账本回滚；清理失败会作为错误返回，不会报告虚假成功。
