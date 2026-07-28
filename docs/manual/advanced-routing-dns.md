---
title: 高级路由、策略组与 DNS
description: 分组选择、复合路由、规则集、DNS 多出口、策略语法和响应处理
---

# 高级路由、策略组与 DNS

路由决定连接走哪个出站，DNS 决定域名如何得到地址。两者可以引用相同的节点和
分组，但执行阶段不同。复杂配置应先稳定命名，再分别设计策略组、连接路由和 DNS
策略。

可直接执行静态校验的完整文件见
[高级路由与 DNS 示例](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/routing-dns.yaml)。

## 策略组完整语义

```yaml
groups:
  latency:
    choose: fast
    use: [primary, backup]
    prefer: [HK, JP, SG]
    avoid: [expired, traffic]
    check: https://www.gstatic.com/generate_204
    expected-status: 200-299
    interval: 30s
    idle-timeout: 5m
    tolerance: 50
    unified-delay: true
    filter: "^(HK|JP|SG)"
    exclude-filter: "到期|流量"
    exclude-type: "direct|http"
    max-failed-times: 3
    test-timeout: 5s

  quality:
    choose: smart
    use: [primary]
    prefer: [premium]
    avoid: [expired]
    check: https://www.gstatic.com/generate_204
    sticky: site

  manual:
    choose: manual
    use: [nodes, primary]
    hidden: false
    icon: "base64:iVBORw0KGgoAAAANSUhEUg..."

  spread:
    choose: spread
    use: [primary]
    avoid: [trial]
    strategy: sticky-sessions
    disable-udp: false
```

字段含义：

| 字段 | 作用 |
| --- | --- |
| `choose` | `manual`、`smart`、`fast`、`stable`、`spread`。`chain` 仍在解析枚举中，但当前会在编译期拒绝 |
| `use` | 候选来源，可引用 feed 名、保留来源 `nodes` 或具体节点 |
| `prefer` | 名称包含匹配。Fast 在延迟差不超过 `tolerance` 时优先，Stable 先检查优先节点，Smart 作为评分加成 |
| `avoid` | 自动策略的降级候选。其它候选全部不可用时才兜底，Smart 在所有候选都命中时恢复全量评分 |
| `check` | HTTP 或 HTTPS 健康检查 URL。探测通过任意支持 TCP 的出站适配器执行，不限定节点协议 |
| `expected-status` | 成功状态码表达式，例如 `200-299/401/403`。空值接受任意有效 HTTP 状态 |
| `interval` | 活跃组的探测间隔，最小 `1s` |
| `idle-timeout` | 组多久没有参与真实选路后停止周期探测，必须不小于 `interval` |
| `tolerance` | Fast 的切换迟滞，单位毫秒 |
| `unified-delay` | 覆盖全局统一延迟。启用后在同一 TCP/TLS 连接上完成第二次请求，以稳态响应耗时作为结果 |
| `strategy` | Spread 算法：`consistent-hashing`、`round-robin`、`sticky-sessions` |
| `filter` | 只保留匹配节点名的正则。多条正则用反引号分隔 |
| `exclude-filter` | 排除匹配节点名的正则。多条正则用反引号分隔 |
| `exclude-type` | 排除协议名，使用 `|` 分隔 |
| `max-failed-times` | 在 `test-timeout` 窗口内达到该拨号失败次数后触发按需探测 |
| `test-timeout` | 连续拨号失败的统计窗口，也是按需探测的超时上限 |
| `disable-udp` | 从选择入口拒绝该组的 UDP，不只影响 API 展示 |
| `sticky` | Smart 的组级覆盖：`off`、`site`、`session`。省略时继承顶层 `smart.sticky` |
| `hidden` | 在支持该字段的 Clash Dashboard 中隐藏 |
| `icon` | URL、路径、data URI、`base64:` 前缀或原始 Base64 图像。Base64 会归一化为 data URI |

`fast` 使用 URLTest 延迟和迟滞选择。`stable` 按优先层级选第一个存活节点。
`spread` 只在存活候选间分配。`smart` 综合 P50、P90、抖动、成功率、退化基线、
被动吞吐、活跃连接、站点记忆和冷却状态。`manual` 完全服从用户选择。

### Pin 固定节点

Clash 兼容接口对 Manual、Smart、Fast、Stable 和 Spread 使用同一套 pin 状态：

```bash
curl -X PUT \
  -H "Content-Type: application/json" \
  -d '{"name":"HK-01"}' \
  http://127.0.0.1:9090/proxies/latency
```

pin 与策略组名一起写入 `database.path` 指定的 Turso 数据库，核心重启后恢复。
API 只有在数据库提交成功后才返回成功。响应中的 `fixed` 是节点名，`pin` 还包含
`generation`、`createdAt`、`source`、`persistent` 和 `available`。

Manual 的 pin 一直生效，直到显式清除。自动策略的 pin 是用户优先级：节点存活时
强制使用，节点失活时运行时临时故障转移，但数据库中的 pin 不删除；节点恢复后会
继续使用。

对自动策略调用组测速会在至少一个节点测试成功后解除测速开始时看到的 pin：

```bash
curl \
  "http://127.0.0.1:9090/group/latency/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=5000"
```

解锁使用 pin 世代校验。测速过程中发生的新选择不会被旧测速结果清除。全部测试
失败时也不会清除。解锁成功后立即根据刚写入的健康数据恢复自动选择，`now` 与
下一条真实流量一致。Manual 组测速只更新健康历史，不解除选择。

可以使用以下任一方式清除：

```bash
curl -X DELETE http://127.0.0.1:9090/proxies/latency
curl -X PUT -H "Content-Type: application/json" -d '{"name":""}' \
  http://127.0.0.1:9090/proxies/latency
```

### URLTest 调度

URLTest 只调度参与过真实选路且仍在 `idle-timeout` 内的组。启动时不会扫描所有
订阅节点。批量探测使用惰性有界并发，同一节点和 URL 的并发请求会合并；失败后
按 5 秒起步指数退避。多个组共享节点时使用最短的请求间隔。订阅删除节点后对应
探测状态会立即回收，每个节点最多保留 16 个测速 URL 的历史。

HTTP 响应头会完整读取，最大 32 KiB，IPv6 authority、查询参数、HTTP/1.0 关闭
语义和 HTTP/1.1 keep-alive 都会正确处理。HTTPS 固定协商 HTTP/1.1，避免用
HTTP/1.1 请求误连到 HTTP/2。历史同时暴露连接、TLS 握手、响应和统一延迟字段。

`chain` 虽然保留在枚举中，但当前运行计划明确未实现，`check` 会失败。多跳出站应
使用节点的 `streamSettings.sockopt.dialerProxy`，并接受其无环约束。

### 候选来源

`use` 中的名字按以下顺序解析：

1. 匹配 feed 名时展开该订阅的当前节点。
2. `nodes` 展开全部手动节点。
3. 匹配具体节点名时只加入该节点。
4. 找不到任何来源时配置失败。

订阅刷新可能改变组内候选，因此 `prefer` 和 `avoid` 应匹配稳定的重命名结果。不要
使用订阅提供方随时会变化的临时流量文字作为唯一选择条件。

## 路由执行顺序

```yaml
route:
  preset: cn_smart
  steps:
    - domain:
        - api.internal.example
        - auth.internal.example
      network: [tcp]
      outbound: direct

    - suffix: [openai.com, github.com]
      network: [tcp, udp]
      outbound: quality

    - "set:private -> direct"
    - "telegram -> latency"
    - "ads -> block"

  final: latency
```

执行过程：

1. 按 `steps` 原始顺序匹配。
2. 命中第一条终结规则后停止。
3. 没有命中自定义规则时执行 `preset` 提供的规则。
4. 最终仍未命中时使用 `final`。

`final` 只能是分组名、`direct` 或 `block`。不应把节点名直接作为最终动作，先把
节点放进策略组，才能统一健康检查和运行时切换。

## 结构化规则的 AND 与 OR

一条结构化规则内，同一字段的多个值是 OR，不同字段之间是 AND：

```yaml
route:
  steps:
    - domain: [api.example.com, auth.example.com]
      port: [443, 8443]
      network: [tcp]
      process: [curl, wuther-ui]
      outbound: direct
```

这条规则表示：

```text
(domain 为 api 或 auth)
并且
(port 为 443 或 8443)
并且
(network 为 tcp)
并且
(process 为 curl 或 wuther-ui)
```

空列表不是通配符，缺少所有 matcher 的规则也不是默认规则，两者都会失败。默认动作
应写在 `route.final`。

结构化规则可使用：

| 字段 | 匹配对象 |
| --- | --- |
| `match` | 兼容表达式或组合匹配 |
| `domain` | 完整域名 |
| `suffix` | 域名后缀 |
| `keyword` | 域名包含文本 |
| `ip` | 目标 IP 或 CIDR |
| `port` | 端口或范围 |
| `process` | 进程名 |
| `set` | 规则集 |
| `network` | `tcp` 或 `udp` |
| `proto` | 协议嗅探结果 |
| `outbound` | 分组、`direct` 或 `block` |

## 路由 DSL

简写格式为 `左侧 -> 出站`：

```yaml
route:
  steps:
    - "domain:api.example.com -> direct"
    - "suffix:example.net -> quality"
    - "ip:10.0.0.0/8 -> direct"
    - "port:22 -> manual"
    - "network:udp -> latency"
    - "process:git -> quality"
    - "set:streaming -> latency"
    - "proto:bittorrent -> block"
    - "sni:cdn.example.com -> quality"
    - "github -> quality"
    - "ads -> block"
  final: latency
```

左侧完整写法：

| 写法 | 含义 |
| --- | --- |
| `home` | 家庭或本地网络规则 |
| `cn` | 中国大陆预置规则 |
| `ads` | 广告规则 |
| `any`、`*`、`final`、`default` | 任意请求 |
| `domain:NAME` | 完整域名 |
| `domain-suffix:NAME` 或 `suffix:NAME` | 后缀 |
| `ip:CIDR` | IP 或网段 |
| `port:PORT` | 目标端口 |
| `network:tcp` | 网络类型 |
| `process:NAME` | 进程名 |
| `set:NAME` | 规则集 |
| `proto:NAME` | 嗅探协议 |
| `sni:NAME` | TLS Server Name |

裸名称 `telegram`、`youtube`、`netflix`、`github`、`apple` 和 `google` 使用
内置服务匹配。其它裸名称按服务名处理，不会自动变成域名后缀。

## Mihomo classical 兼容范围

规则集中的 classical 行支持：

```text
DOMAIN,api.example.com,quality
DOMAIN-SUFFIX,example.net,quality
DOMAIN-KEYWORD,video,latency
IP-CIDR,10.0.0.0/8,DIRECT
IP-CIDR6,2001:db8::/32,DIRECT
DST-PORT,8000-8999,manual
PROCESS-NAME,curl,DIRECT
NETWORK,udp,latency
RULE-SET,streaming,latency
MATCH,latency
```

端口支持单值和闭区间 `LOW-HIGH`。

当前明确不支持：

- `SRC-IP-CIDR`
- `SRC-PORT`
- `DOMAIN-REGEX`
- `PROCESS-PATH`

不支持的类型会报错，不能依赖静默跳过。

## 规则集

`route.sets` 定义命名规则集，`route.rule_set` 是兼容别名入口。规则集可以来自文件、
远程 URL 或内联内容：

```yaml
route:
  sets:
    private:
      type: ipcidr
      payload:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16

    streaming:
      type: classical
      format: yaml
      url: https://rules.example.com/streaming.yaml
      every: 12h
      via: direct

    internal-domains:
      type: domain
      format: text
      path: /etc/wuther/rules/internal.txt

  steps:
    - "set:private -> direct"
    - "set:internal-domains -> direct"
    - "set:streaming -> quality"
  final: latency
```

设计原则：

- 只有 `payload` 时是内联规则集。
- 只有 `path` 时是本地规则集。
- 有 `url` 时是远程规则集，`path` 可作为显式缓存路径。
- `via` 决定远程规则集通过哪个出站下载。
- `every` 决定刷新周期。
- `type` 表示规则行为，常用 `domain`、`ipcidr` 和 `classical`。
- `format` 表示正文格式，例如 `yaml`、`text` 或 `mrs`。

远程规则集首次下载失败且没有缓存时不可用。更新失败时保留上次成功内容，避免把
正在工作的规则替换为空。

## DNS 对象模型

高级 DNS 可以组合命名服务器、多出口和嵌套组：

```yaml
resolver:
  mode: smart
  fake: auto
  ipv6: true
  listen: 127.0.0.1:1053

  servers:
    cf:
      endpoint: https://1.1.1.1/dns-query
      exits: [quality, latency, DIRECT]
      strategy: adaptive
      timeout: 3s
      max-parallel: 2

    google:
      endpoint: tls://8.8.8.8
      exits: [quality, DIRECT]
      strategy: round-robin
      timeout: 3s

    ali: https://223.5.5.5/dns-query

  groups:
    domestic:
      members: [ali, udp://119.29.29.29]
      strategy: parallel
      timeout: 2s
      max-parallel: 2

    public:
      members: [cf, google]
      strategy: adaptive
      timeout: 4s
      max-parallel: 2

  nameserver: [public]
  fallback: [domestic]
  proxy-server-nameserver: [domestic]
  direct-nameserver: [domestic]
```

### server 与 group 的区别

`servers.NAME` 表示一个 DNS endpoint，可以配置多个 `exits`。同一个 DoH 或 DoT
服务可以经不同代理出口访问。

`groups.NAME` 表示多个服务器或 endpoint 的集合，成员还可以是另一个 group。嵌套
引用必须无环。

两层都支持策略：

| 策略 | 行为 |
| --- | --- |
| `round-robin` | 按顺序轮换 |
| `random` | 随机选择 |
| `parallel` | 并行查询并采用可用响应 |
| `adaptive` | 根据运行结果调整 |
| `sequential` 或 `fallback` | 依次回退 |
| `all` | 查询全部成员 |

`timeout` 控制单次策略等待，`max-parallel` 限制并行查询数量。未设置时由上层默认值
决定。

### 三类默认 nameserver

| 字段 | 使用场景 |
| --- | --- |
| `nameserver` | 普通代理查询 |
| `proxy-server-nameserver` | 解析代理节点本身的域名，避免启动环 |
| `direct-nameserver` | 直连规则的域名查询 |

代理节点地址是域名时，必须确保 `proxy-server-nameserver` 不依赖这个代理节点才能
访问。最稳妥的 bootstrap 是可直连的 UDP、DoT 或 DoH endpoint。

## nameserver policy

`nameserver-policy` 根据域名或规则集选择 DNS 服务，值可以是单个名字或列表：

```yaml
resolver:
  nameserver-policy:
    "geosite:cn": domestic
    "rule-set:internal-domains": domestic
    "ruleset:streaming": [public, domestic]
    "openai.com,github.com": public
```

policy key 支持 `geosite:`、`rule-set:` 和 `ruleset:`。多个条件可以用逗号分隔。
policy 先决定查询目标，DNS `rules` 再处理查询或响应。

## DNS 结构化规则

```yaml
resolver:
  rules:
    - suffix: internal.example
      route: domestic
      strategy: sequential
      no_cache: true

    - domain: telemetry.example.com
      reject: true
      no_drop: true

    - set: ad-domains
      nxdomain: true

    - suffix: service.example
      evaluate: public
      no_optimistic_cache: true

    - match_response: 10.0.0.0/8
      respond: true
      ttl: 30

    - suffix: lab.example
      accept:
        - 192.0.2.10
        - 2001:db8::10
      ttl: 60
```

匹配字段优先级：

1. `match`
2. `domain`
3. `suffix` 或 `host`
4. `keyword`
5. `set`、`geosite`、`geoip` 或 `ruleset`
6. `match_response` 或 `response`
7. 缺少匹配字段时为 Any

常用选项：

| 选项 | 作用 |
| --- | --- |
| `no_cache` | 不写入普通缓存 |
| `no_optimistic_cache` | 不写入乐观缓存 |
| `ttl` | 覆盖响应 TTL |
| `client_subnet` 或 `ecs` | 设置 EDNS Client Subnet |
| `strategy` | 覆盖本次查询的服务器选择策略 |

动作按确定优先级解析。常用动作有 `drop`、`reject`、`nxdomain`、`noerror`、
`servfail`、`formerr`、`notimp`、`accept`、`fake`、`respond`、`evaluate`、
`route`、`direct` 和 `proxy`。

## DNS 字符串 DSL

DNS 规则也可写成字符串：

```yaml
resolver:
  rules:
    - "=api.internal.example -> direct?nocache"
    - "*.internal.example -> domestic?ttl=60"
    - "~telemetry -> reject?no_drop"
    - "set:ad-domains -> nxdomain"
    - "suffix:service.example -> evaluate:public?nooptcache"
    - "match_response:10.0.0.0/8 -> respond?ttl=30"
    - "any -> proxy:public?strategy=adaptive"
```

左侧语法：

| 写法 | 含义 |
| --- | --- |
| `any`、`*`、`final` | 任意查询 |
| `=NAME` | 完整域名 |
| `*.NAME` | 域名后缀 |
| `~TEXT` | 域名关键词，不是正则表达式 |
| `domain:NAME` | 完整域名 |
| `suffix:NAME` | 后缀 |
| `keyword:TEXT` | 关键词 |
| `set:NAME`、`geosite:NAME`、`geoip:NAME`、`ruleset:NAME` | 数据集 |
| `match_response:CIDR` 或 `response:CIDR` | 上一步得到的响应地址 |
| `not:EXPR` | 反向匹配 |
| 裸域名 | 后缀匹配 |

右侧语法：

| 写法 | 行为 |
| --- | --- |
| `reject` 或 `block` | 返回拒绝，可附加 method 和 no_drop |
| `drop` | 丢弃查询 |
| `refuse` | 返回 REFUSED |
| `nxdomain` | 返回 NXDOMAIN |
| `noerror` | 返回空 NOERROR |
| `servfail`、`formerr`、`notimp` | 返回对应 DNS 状态 |
| `fake` | 返回 fake IP |
| `accept` 或 `hosts` | 返回指定地址 |
| `direct` | 使用直连 DNS |
| `proxy:GROUP` 或 `route:GROUP` | 交给指定 DNS 服务或组 |
| `evaluate:GROUP` | 查询并保存结果，继续匹配后续响应规则 |
| `respond` | 返回已保存响应 |

查询选项放在 `?` 后，支持 `nocache`、`nooptcache`、`ttl=SECONDS`、
`ecs=ADDRESS` 和 `strategy=NAME`。

## `evaluate` 与响应匹配

`evaluate` 是非终结动作。它先取得一个响应，把地址保存到上下文，再继续执行后面的
`match_response`：

```yaml
resolver:
  rules:
    - "suffix:service.example -> evaluate:public?nooptcache"
    - "match_response:10.0.0.0/8 -> reject?no_drop"
    - "match_response:2001:db8::/32 -> respond?ttl=30"
    - "suffix:service.example -> respond"
```

这可以按解析结果决定接受或拒绝，而不是只按查询名分类。`respond` 之前必须已经有
可返回的保存响应。

## 拒绝节流

默认 `reject` 会在同类请求 30 秒内达到 50 次后从 REFUSED 转为直接丢弃，避免
高频客户端持续放大本机负载。需要始终返回明确状态时设置 `no_drop`。公网 DNS
监听不应仅依赖此机制，仍需防火墙、访问控制和速率限制。

## Fake IP 与系统接管

Fake IP 只有在流量能够回到内核时才有意义：

1. DNS 返回 fake 地址。
2. 系统或应用把后续连接交给 TUN、透明代理或受控本地代理。
3. 内核从 fake 地址还原域名。
4. 路由按域名和其它条件匹配。

只开启 `resolver.fake`，却没有正确的 capture 或应用代理，会让客户端连接到不可达
地址。路由器方案应配合 DNS hijack，桌面方案应确保系统代理或 TUN 已生效。

## 完整组合示例

```yaml
groups:
  latency:
    choose: fast
    use: [primary]
    prefer: [HK, JP, SG]
    check: https://www.gstatic.com/generate_204
    sticky: site

  quality:
    choose: stable
    use: [primary]
    prefer: [premium]
    check: https://www.gstatic.com/generate_204

route:
  preset: cn_smart
  sets:
    private:
      type: ipcidr
      payload: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
    streaming:
      type: classical
      format: yaml
      url: https://rules.example.com/streaming.yaml
      every: 12h
      via: direct
  steps:
    - "set:private -> direct"
    - "ads -> block"
    - "set:streaming -> quality"
    - "github -> quality"
  final: latency

resolver:
  mode: smart
  fake: auto
  servers:
    public-doh:
      endpoint: https://1.1.1.1/dns-query
      exits: [quality, latency, DIRECT]
      strategy: adaptive
      timeout: 3s
      max-parallel: 2
    domestic-doh: https://223.5.5.5/dns-query
  groups:
    public: [public-doh]
    domestic: [domestic-doh, udp://119.29.29.29]
  nameserver: [public]
  fallback: [domestic]
  proxy-server-nameserver: [domestic]
  direct-nameserver: [domestic]
  nameserver-policy:
    "geosite:cn": domestic
    "rule-set:streaming": public
  rules:
    - "set:ad-domains -> nxdomain"
    - "suffix:internal.example -> direct?nocache"
    - "any -> proxy:public?strategy=adaptive"
```

上线前用 `check` 验证全部引用，再用 `explain` 检查展开后的规则顺序。路由错误最常见
的原因不是语法，而是规则顺序、名称重写和 bootstrap DNS 形成隐式依赖。
