---
title: 策略组、路由与 DNS
description: 候选节点选择、路由规则、规则集、DNS 服务和 Fake IP
---

# 策略组、路由与 DNS

本页说明通用模型。复合 AND 和 OR 规则、Mihomo classical 兼容边界、规则集、
DNS 多出口、`evaluate` 与 `respond` 响应链见
[高级路由、策略组与 DNS](advanced-routing-dns.md)。

数据连接先由路由规则决定出站或分组，再由分组策略选择具体节点。DNS 有独立的服务、
出口和组调度，但 DNS 命名出口可以引用同一节点集合。

完整字段见[路由与 DNS 字段索引](generated/routing-dns.md)。

## 策略组

```yaml
groups:
  香港节点:
    choose: smart
    include-all-providers: true
    filter: '(?i)(香港|\bHK\b|Hong[ _-]?Kong)'
    empty-fallback: DIRECT
    check: https://www.gstatic.com/generate_204
    sticky: site

  节点选择:
    choose: manual
    proxies: [香港节点, 日本节点]
    default-selected: 香港节点
    empty-fallback: DIRECT
```

### 字段

| 字段 | 说明 |
| --- | --- |
| `choose` | 选择算法 |
| `proxies` | 显式节点或下级策略组，也接受 `members` |
| `use` | provider 名，兼容 `nodes`, 节点名或组名 |
| `include-all` | 纳入全部静态节点和 provider |
| `include-all-proxies` | 纳入全部静态节点 |
| `include-all-providers` | 纳入全部 provider |
| `include-nodes`, `exclude-nodes` | 使用 glob 纳入或排除静态节点 |
| `include-providers`, `exclude-providers` | 使用 glob 纳入或排除 provider |
| `include-groups`, `exclude-groups` | 使用 glob 纳入或排除下级组 |
| `min-members`, `max-members` | 设置最少和最多可用候选数 |
| `default-selected` | Manual 没有 pin 时的默认直接成员 |
| `empty-fallback` | 候选不足时使用的直连, 阻断或静态节点 |
| `weights` | Weighted 使用的成员名 glob 权重表 |
| `lazy` | 闲置时是否停止周期健康检查 |
| `prefer` | 节点名偏好模式 |
| `avoid` | 节点名回避模式 |
| `check` | 健康检查 URL |
| `sticky` | 粘性模式字符串 |
| `path` | 多跳链路使用的路径 |

### 选择算法

| 值 | 行为 |
| --- | --- |
| `manual` | 使用 API 或持久化状态指定节点 |
| `smart` | 综合历史成功率、延迟和 Smart 目标 |
| `fast` | 更强调当前延迟 |
| `stable` | 更强调历史稳定性 |
| `spread` | 在可用节点间分散负载 |
| `random` | 在健康候选之间无偏随机选择 |
| `weighted` | 按 `weights` 中的 glob 权重随机选择 |
| `chain` | 多跳链路入口，当前实现不完整的组合会在编译期拒绝 |

`prefer` 和 `avoid` 作用于订阅完成重命名后的最终节点名。候选集为空时不会凭空生成
代理节点。是否允许直连兜底由 `empty-fallback` 明确决定。

上层分流组可以引用下级节点组。上层必须使用 `manual`，下级自动组直接管理节点和
provider。路由与 DNS 会递归得到最终节点，并把完整选择链暴露给 Clash API。配置
编译器会拒绝循环引用并返回实际循环路径。

## 路由执行顺序

`route.steps` 自上而下执行，首个命中步骤返回 action。没有步骤命中时使用
`route.final`。`route.preset` 会在编译阶段加入预设规则。

```yaml
route:
  preset: cn_smart
  final: main
  steps:
    - {domain: internal.example, outbound: direct}
    - {suffix: example.org, port: 443, outbound: main}
    - {set: ads, outbound: block}
```

## 路由步骤的四种写法

### WutherCore 字符串

```yaml
route:
  steps:
    - "port:53 -> direct"
    - "set:openai -> ai"
```

### Mihomo classical 字符串

```yaml
route:
  steps:
    - "DST-PORT,53,DNS_Hijack"
```

### Mihomo mapping

```yaml
route:
  steps:
    - match: "DST-PORT,53"
      outbound: DNS_Hijack
```

### 类型化对象

```yaml
route:
  steps:
    - port: [53, 5353]
      network: udp
      outbound: DNS_Hijack
    - suffix: example.com
      port: 443
      outbound: direct
```

类型化对象是推荐写法。对象不需要先转成 DSL 再解析，拼错字段会因未知字段拒绝而
立即失败。

## 匹配字段

| 标准字段 | 兼容别名 | 含义 |
| --- | --- | --- |
| `match` | `rule` | Mihomo classical 的 `TYPE,VALUE` |
| `domain` | 无 | 完整域名相等 |
| `suffix` | `domain-suffix`、`domain_suffix` | 域名后缀 |
| `keyword` | `domain-keyword`、`domain_keyword` | 域名子串 |
| `ip` | `cidr`、`ip-cidr`、`ip_cidr` | IP 或 CIDR |
| `port` | `dst-port`、`dst_port` | 目的端口或范围 |
| `process` | `process-name`、`process_name` | 进程名 |
| `set` | `rule-set`、`rule_set` | 外部规则集 |
| `network` | 无 | `tcp` 或 `udp` |
| `proto` | 无 | `tls`、`quic`、`stun`、`http`、`webrtc` 等指纹 |
| `outbound` | `proxy`、`target`、`action` | 节点、分组、`direct` 或 `block` |

对象至少需要一个匹配来源，且必须有 `outbound`。同一对象内不同字段按 AND 组合。
单字段写列表时按 OR 组合。`MatcherValue` 接受字符串、整数、布尔值或这些标量的
列表，编译阶段再按字段类型解析。

## 路由动作

动作可以是：

- 节点名。
- 分组名。
- `direct`。
- `block`。
- 运行时注册的特殊处理器，例如配置实际提供的 DNS Hijack。

引用不存在时 `check` 会失败。节点和分组重名会造成不明确配置，应使用稳定命名
规则避免。

## WutherCore 规则集

```yaml
route:
  sets:
    ads:
      type: domain
      format: mrs
      url: https://example.com/ads.mrs
      path: data/rulesets/ads.mrs
      every: 24h
      via: direct
```

| 字段 | 说明 |
| --- | --- |
| `url` | 远程来源 |
| `path` | 没有 URL 时是本地来源，有 URL 时是显式缓存位置 |
| `payload` | 内联规则列表 |
| `type` | 规则行为类型，默认 `domain` |
| `format` | `yaml`、`txt`、`list`、`json`、`mrs`、`srs`、`rrs` 等 |
| `every` | 刷新周期，默认 24 小时 |
| `via` | 下载使用的出站 |

规则集在步骤中通过 `set` 匹配。首次下载未完成时，未加载的规则集不能伪造命中，
流量继续检查后续步骤或落到 `final`。

## 第三方规则集入口

### sing-box

`route.rule_set` 和别名 `route.rule-set` 接受 sing-box `inline`、`local`、
`remote` 配置。`tag` 可以是单字符串或字符串列表。编译阶段严格检查 source kind、
path、URL、内联 rules、更新时间和 download detour，再合并到统一 `route.sets`。

### Mihomo

顶层 `rule-providers` 接受 `http`、`file`、`inline`。`behavior`、`format`、
`interval`、`proxy` 等字段在编译阶段映射为统一规则集。Mihomo 的整数秒和
sing-box 的时长字符串都由 `CompatDuration` 接受。

## 规则集命令

```bash
wuther-core ruleset list config.yaml
wuther-core ruleset refresh config.yaml --cache-dir data/rulesets
wuther-core ruleset convert input.yaml output.rrs
wuther-core ruleset convert input.rrs output.txt --output-format txt
```

## DNS 总体结构

```yaml
resolver:
  mode: normal
  fake: auto
  cache: 1h
  ipv6: true
  ipv6-timeout: 100ms
  use-hosts: true
  use-system-hosts: true

  servers:
    cloudflare:
      endpoint: https://1.1.1.1/dns-query
      exits: [proxy-a, proxy-b, DIRECT]
      strategy: adaptive
      timeout: 3s
      max-parallel: 2

  groups:
    public:
      members: [cloudflare, tls://9.9.9.9:853]
      strategy: parallel
      timeout: 4s
      max-parallel: 2

  nameserver: [public]
  fallback: [cloudflare]
  listen: 127.0.0.1:1053
```

## DNS 模式

| 标准值 | 兼容值 | 行为 |
| --- | --- | --- |
| `system` | 无 | 使用系统解析路径 |
| `normal` | `secure`、`smart` | 使用配置的 DNS 服务和规则 |
| `fake` | 无 | 使用 Fake IP 主模式 |

`fake` 字段进一步控制 Fake IP：

| 值 | 行为 |
| --- | --- |
| `off` | 不合成 Fake IP |
| `auto` | 与 Capture 和查询类型协同决定 |
| `force` | 对支持的 A 和 AAAA 查询强制 Fake IP |

普通模式会保留 TXT、MX、SRV、CAA、DNSSEC、SVCB、HTTPS、ANY 和未知 QTYPE。
Fake IP 只对 A 和 AAAA 合成。

## DNS 基础字段

| 字段 | 说明 |
| --- | --- |
| `cache` | DNS 缓存有效期 |
| `ipv6` | 是否允许 AAAA 结果 |
| `ipv6-timeout` | 双栈策略等待 IPv6 的时间 |
| `use-hosts` | 是否使用配置内 `hosts` |
| `use-system-hosts` | 是否读取系统 hosts |
| `hosts` | 静态域名映射 |
| `fake-ip-filter` | 不使用或只使用 Fake IP 的域名列表 |
| `fake-ip-filter-mode` | `blacklist` 或 `whitelist` |
| `prefer-h3` | DoH 可用时是否偏好 HTTP/3 |
| `listen` | 独立 DNS UDP 和 TCP 监听地址，空值表示不启动 |

## 命名 DNS 服务

`servers` 的值可以是 endpoint 字符串：

```yaml
resolver:
  servers:
    ali: https://223.5.5.5/dns-query
```

也可以是高级对象：

```yaml
resolver:
  servers:
    ali:
      endpoint: https://223.5.5.5/dns-query
      exits: [DIRECT]
      strategy: sequential
      timeout: 5s
      max-parallel: 1
```

高级字段：

- `endpoint` 是唯一 DNS 服务地址。
- `exits` 是访问这个 endpoint 的节点列表，空列表使用默认直连 DNS socket。
- `strategy` 只调度出口。
- `timeout` 限制服务查询。
- `max-parallel` 只对并发策略生效，最小按 1 处理。

DoH、DoT、TCP 和 UDP DNS 可以使用命名出口。DoQ 需要完整代理数据报通道，目前
不能假设所有出站都可承载。

## DNS 服务组

列表短写：

```yaml
resolver:
  groups:
    domestic: [udp://223.5.5.5, udp://119.29.29.29]
```

对象长写：

```yaml
resolver:
  groups:
    public:
      members: [cloudflare, google]
      strategy: parallel
      timeout: 4s
      max-parallel: 2
```

成员可以引用命名 server、其它 group 或直接写 endpoint。组保留嵌套边界，不会
把所有成员拍平成一个无限并发列表。

## DNS 调度策略

| 值 | 行为 |
| --- | --- |
| `round-robin` | 每次从下一个成员开始，失败后继续 |
| `random` | 均匀随机起点，失败后尝试剩余成员 |
| `parallel` | 有界并发，首个成功答案返回 |
| `adaptive` | 根据历史平均 RTT 加权，默认策略 |
| `sequential` | 按顺序故障转移，兼容别名 `fallback` |
| `all` | 有界并发，合并所有成功答案 |

server 的策略调度代理出口，group 的策略调度 DNS 服务。这两个层次各自遵守
`max-parallel`，不会互相替代。

## DNS 路由入口

| 字段 | 用途 |
| --- | --- |
| `nameserver` | 常规查询入口 |
| `fallback` | fallback 服务入口 |
| `default-nameserver` | 启动和解析 DNS 服务域名时的基础入口 |
| `nameserver-policy` | 按域名或规则集选择服务 |
| `proxy-server-nameserver` | 解析代理服务器域名 |
| `proxy-server-nameserver-policy` | 代理服务器域名的策略 |
| `direct-nameserver` | 直连路径专用解析 |
| `direct-nameserver-follow-policy` | 直连解析是否继续遵循策略 |
| `rules` | WutherCore DNS 规则列表 |

入口值可以引用命名 server、group 或直接 endpoint。引用循环会在编译或运行计划
构建阶段拒绝。

## fallback 过滤

`fallback-filter` 包含：

- `geoip`，是否启用 GeoIP 判断。
- `geoip-code`，默认 `CN`。
- `ipcidr`，触发 fallback 的 IP 范围。
- `domain`，触发 fallback 的域名模式。
- `geosite`，触发 fallback 的 geosite 分类。

没有加载相应数据库或规则集时不能假定 GeoIP 或 geosite 会产生匹配。排错时先用
明确域名和 IP 条件建立最小规则。

## Fake IP 与 Capture

Fake IP 必须能在捕获路径中反查回原始域名。常见要求：

- `capture.resolver: hijack` 把应用 DNS 查询送入 WutherCore。
- TUN 路由不能再次捕获访问上游 DNS 的 socket。
- `fake-ip-filter` 排除局域网、系统探测和不兼容域名。
- 关闭 Fake IP 后重新测试，可以区分 DNS 合成问题和路由问题。

系统接管配置见[系统接管](capture.md)。
