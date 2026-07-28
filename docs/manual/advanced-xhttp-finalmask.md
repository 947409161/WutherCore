---
title: 高级 XHTTP、StreamSettings 与 FinalMask
description: XHTTP 模式、独立下载、安全对象、socket 策略、FinalMask 和 QUIC 参数
---

# 高级 XHTTP、StreamSettings 与 FinalMask

这一层同时控制应用传输、独立下载通道、TLS 或 REALITY、系统 socket 与最终数据
变换。字段很多，但层次固定：

可直接执行静态校验的完整文件见
[XHTTP 与 FinalMask 示例](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/xhttp-finalmask.yaml)。

```text
节点协议
  transport.xhttp
    XHTTP 上行与会话
    downloadSettings 独立下行
  secure
    主连接 TLS 或 REALITY
  streamSettings.sockopt
    主连接 socket
  streamSettings.finalmask
    主连接最终 TCP 或 UDP 变换
```

## 完整客户端组合

下面的模板组合 VLESS、REALITY、XHTTP、独立 TLS 下载、socket 策略和 TCP
fragment。占位密钥必须替换：

```yaml
nodes:
  - name: vless-reality-xhttp
    protocol: vless
    address: upload.example.com:443
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
      kind: xhttp
      xhttp:
        host: upload.example.com
        path: /api
        mode: packet-up
        headers:
          Accept-Language: zh-CN,zh;q=0.9
        xPaddingBytes: 100-1000
        xPaddingObfsMode: true
        xPaddingPlacement: queryInHeader
        xPaddingMethod: tokenish
        sessionIDPlacement: cookie
        sessionIDKey: sid
        sessionIDTable: alphanumeric
        sessionIDLength: 16-24
        seqPlacement: header
        seqKey: X-Sequence
        uplinkHTTPMethod: POST
        uplinkDataPlacement: body
        uplinkChunkSize: 65536-262144
        scMaxEachPostBytes: 1048576
        scMinPostsIntervalMs: 20
        scMaxBufferedPosts: 64
        serverMaxHeaderBytes: 32768
        xmux:
          maxConnections: 2-4
          cMaxReuseTimes: 32-64
          hMaxRequestTimes: 100-200
          hMaxReusableSecs: 300-600
          hKeepAlivePeriod: 30
        downloadSettings:
          address: download.example.com
          port: 443
          network: xhttp
          security: tls
          tlsSettings:
            serverName: download.example.com
            alpn: [h2]
            fingerprint: chrome
            enableSessionResumption: true
            pinnedPeerCertSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
          xhttpSettings:
            host: download.example.com
            path: /download
            mode: stream-up
            xPaddingBytes: 100-400
            xmux:
              maxConcurrency: 8-16
          sockopt:
            domainStrategy: UseIPv4v6
            tcpFastOpen: true
            happyEyeballs:
              prioritizeIPv6: false
              interleave: 1
              tryDelayMs: 250
              maxConcurrentTry: 4
    streamSettings:
      network: xhttp
      sockopt:
        domainStrategy: UseIPv4v6
        tcpFastOpen: true
        tcpKeepAliveIdle: 60
        tcpKeepAliveInterval: 15
        addressPortStrategy: none
        happyEyeballs:
          prioritizeIPv6: false
          interleave: 1
          tryDelayMs: 250
          maxConcurrentTry: 4
      finalmask:
        tcp:
          - type: fragment
            settings:
              packets: tlshello
              length: 20-80
              delay: 0-5
              maxSplit: 4
```

主连接使用 REALITY，独立下载连接使用普通 TLS。两套安全对象分别验证，主连接设置
不会自动复制到下载端。

## 四种模式

| 模式 | 上行形态 | 下行形态 | 适用情况 |
| --- | --- | --- | --- |
| `auto` | 根据运行环境选择 | 根据运行环境选择 | 普通兼容配置 |
| `stream-one` | 单个双向流 | 同一连接 | 最简单，不支持独立下载 |
| `stream-up` | 流式上行 | 流式响应 | 支持独立下载 |
| `packet-up` | 分块请求 | 独立响应流 | 可精细控制请求布局 |

模式约束：

- `downloadSettings` 不能用于 `stream-one`。
- `uplinkDataPlacement` 的 `cookie` 和 `header` 只用于 `packet-up`。
- `uplinkHTTPMethod: GET` 只用于 `packet-up`。
- `scMaxBufferedPosts` 有防御性上限，不能用极大值绕过内存约束。
- 嵌套 `downloadSettings` 最深 8 层，但生产配置通常只需要一层。

## 会话、序号和填充位置

XHTTP 把会话标识、请求序号、上行数据和填充放入不同 HTTP 位置。可选值：

| 字段 | 可选值 |
| --- | --- |
| `xPaddingPlacement` | `cookie`、`header`、`query`、`queryInHeader` |
| `xPaddingMethod` | `repeat-x`、`tokenish` |
| `sessionIDPlacement` | `path`、`cookie`、`header`、`query` |
| `seqPlacement` | `path`、`cookie`、`header`、`query` |
| `uplinkDataPlacement` | `auto`、`body`、`cookie`、`header` |

每个 placement 对应的 key 应同步配置：

```yaml
xPaddingPlacement: header
xPaddingHeader: X-Padding
sessionIDPlacement: cookie
sessionIDKey: sid
seqPlacement: query
seqKey: seq
uplinkDataPlacement: body
```

`sessionIDTable` 非空时必须设置 `sessionIDLength`。自定义表只能包含 ASCII，并且
字符表与长度组合必须提供足够大的 ID 空间。`xPaddingBytes` 非零范围的下界不能为
零，也不能超过实现的保护上限。

## 托管请求头

`headers` 只接受普通自定义请求头。Host、XHTTP framing 和 hop by hop 请求头由
运行时管理，不能在这里覆盖。非法 header name、换行和其它非法值会在启动前失败。

```yaml
headers:
  Accept-Language: zh-CN,zh;q=0.9
  X-Client: WutherCore
```

Host 应写在 `xhttp.host`，不要放进 `headers`。

## XMUX

XMUX 控制连接数量、并发和复用寿命：

| 字段 | 含义 |
| --- | --- |
| `maxConcurrency` | 单连接最大并发 |
| `maxConnections` | 连接池数量 |
| `cMaxReuseTimes` | 单连接复用次数 |
| `hMaxRequestTimes` | 单个 HTTP 连接请求次数 |
| `hMaxReusableSecs` | HTTP 连接最大复用秒数 |
| `hKeepAlivePeriod` | Keepalive 周期 |

`maxConnections` 与 `maxConcurrency` 不能同时启用。两者代表不同控制模型：

```yaml
xmux:
  maxConnections: 2-4
  cMaxReuseTimes: 32-64
```

或者：

```yaml
xmux:
  maxConcurrency: 8-16
  hMaxRequestTimes: 100-200
```

范围在每次建立资源时取值。固定值可直接写整数。

## 独立下载通道

`downloadSettings` 必须提供非空 `address` 或 `host`，并提供非零 `port`。支持
`none`、`tls` 和 `reality` 三种安全类型。常用字段：

| 字段 | 作用 |
| --- | --- |
| `address` 或 `host` | 下载端目标 |
| `port` | 下载端端口 |
| `method` 或 `network` | 下载传输 |
| `transport` | 强类型传输对象 |
| `xhttpSettings` | 下载端 XHTTP |
| `security` | `none`、`tls` 或 `reality` |
| `tlsSettings` | 下载端 TLS |
| `realitySettings` | 下载端 REALITY |
| `alpn` | 下载端 ALPN |
| `sockopt` | 下载端 socket |
| `finalmask` | 下载端 FinalMask |

安全边界：

- 主连接证书固定不自动应用到下载连接。
- 下载连接使用 TLS 时，应单独设置正确 SNI 和证书校验。
- 下载连接使用 REALITY 时，应单独配置 password 或 public key、short ID 与
  server name。
- 独立下载的 `sockopt.dialerProxy` 也参与引用和环检测。
- `transport.xhttp` 与 `xhttpSettings` 同时出现时，有效配置必须一致。

## TLS 与 ECH

客户端 TLS 对象支持：

- `serverName`
- `alpn`
- `enableSessionResumption`
- `disableSystemRoot`
- `minVersion` 和 `maxVersion`
- `cipherSuites`
- `curvePreferences`
- `fingerprint`
- `certificates`
- `pinnedPeerCertSha256`
- `verifyPeerCertByName`
- `echConfigList`
- ECH 查询和 socket 设置

私有 CA 示例：

```yaml
secure:
  tls: true
  tls-settings:
    serverName: edge.internal.example
    disableSystemRoot: true
    certificates:
      - certificateFile: /etc/wuther/ca/internal-ca.pem
        usage: verify
    verifyPeerCertByName: edge.internal.example
```

证书固定示例：

```yaml
secure:
  tls: true
  tls-settings:
    serverName: edge.example.com
    pinnedPeerCertSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

ECH 必须提供可执行的 ECHConfigList 或查询配置。`secure.ech: true` 却没有任何 ECH
材料会失败。ECH 与 REALITY 互斥。

完整 TLS 字段见 [XHTTP 逐字段索引](generated/xhttp.md)。

## StreamSettings 与 socket

`streamSettings.network` 是最终网络类型，存在时覆盖外层 `transport.kind`。
`sockopt` 直接影响拨号 socket：

```yaml
streamSettings:
  network: raw
  sockopt:
    mark: 255
    tcpFastOpen: 128
    domainStrategy: UseIPv6v4
    tcpKeepAliveIdle: 60
    tcpKeepAliveInterval: 15
    tcpCongestion: bbr
    interface: eth0
    tcpWindowClamp: 65535
    tcpUserTimeout: 15000
    tcpMaxSeg: 1400
    tcpMptcp: false
    addressPortStrategy: srvPortAndAddress
    happyEyeballs:
      prioritizeIPv6: true
      interleave: 1
      tryDelayMs: 250
      maxConcurrentTry: 4
```

### 域名策略

`domainStrategy` 可用：

- `AsIs`
- `UseIP`
- `UseIPv4`
- `UseIPv6`
- `UseIPv4v6`
- `UseIPv6v4`
- `ForceIP`
- `ForceIPv4`
- `ForceIPv6`
- `ForceIPv4v6`
- `ForceIPv6v4`

`Use` 系列在可解析时使用 IP，`Force` 系列要求得到符合策略的 IP，否则失败。
`IPv4v6` 与 `IPv6v4` 表示首选顺序。

### 地址和端口发现

`addressPortStrategy` 可用：

- `none`
- `srvPortOnly`
- `srvAddressOnly`
- `srvPortAndAddress`
- `txtPortOnly`
- `txtAddressOnly`
- `txtPortAndAddress`

这类策略会让 DNS 记录参与目标地址或端口选择。使用前确认权威 DNS 记录受控，避免
把节点目标交给不可信数据。

### Keepalive

`tcpKeepAliveIdle` 与 `tcpKeepAliveInterval` 必须一起启用或一起关闭，符号与开关
状态必须兼容。只设置一个字段会失败。

### 自定义 sockopt

```yaml
streamSettings:
  sockopt:
    customSockopt:
      - system: linux
        network: tcp
        level: "6"
        opt: "1"
        value: "1"
        type: int
```

`opt` 不能为空，`type` 只能是 `int` 或 `str`。Windows 不支持字符串类型自定义
sockopt。错误的 level 和 opt 可能导致拨号失败，只有明确理解目标系统常量时才使用。

### 平台限制

| 设置 | 平台 |
| --- | --- |
| `mark` | Linux、Android、FreeBSD |
| `tcpMptcp` | Linux、Android |
| `tcpCongestion` | Linux、Android |
| `tcpWindowClamp` | Linux、Android |
| `tcpUserTimeout` | Linux、Android |
| `tcpMaxSeg` | Linux、Android |
| `interface` | 受各平台接口绑定能力限制 |

不支持的平台会拒绝配置，不会静默忽略。跨平台共用配置时，把平台专属节点拆分到
独立配置文件。

## FinalMask 结构

FinalMask 位于 `streamSettings.finalmask`：

```yaml
streamSettings:
  finalmask:
    tcp: []
    udp: []
    quicParams: {}
```

TCP 类型：

- `header-custom`
- `fragment`
- `sudoku`
- `xmc`

UDP 类型：

- `header-custom`
- `mkcp-legacy`
- `noise`
- `salamander`
- `sudoku`
- `xdns`
- `xicmp`
- `realm`

每一项都使用：

```yaml
- type: TYPE
  settings:
    FIELD: VALUE
```

未知 `type`、未知字段或错误类型都会失败。

## TCP fragment

```yaml
finalmask:
  tcp:
    - type: fragment
      settings:
        packets: tlshello
        length: 20-80
        delay: 0-5
        maxSplit: 4
```

`packets` 可写 `tlshello`、非零整数或整数范围。`lengths` 和 `delays` 可提供多段
范围，存在时替代单个 `length` 和 `delay`。最终 length 的下界不能为零。

```yaml
finalmask:
  tcp:
    - type: fragment
      settings:
        packets: 1-3
        lengths: [20-40, 100-200, 512-1024]
        delays: [0-2, 1-5]
        maxSplit: 5
```

fragment 只改变写入分段，不等同于新的加密或认证层。

## TCP Sudoku 与 XMC

```yaml
finalmask:
  tcp:
    - type: sudoku
      settings:
        password: replace-me
        ascii: alphanumeric
        paddingMin: 64
        paddingMax: 512
    - type: xmc
      settings:
        hostname: mail.example.com
        usernames: [alice, backup]
        password: replace-me
```

XMC password 不能为空。Sudoku 可使用 `customTable`、`customTables` 以及对应兼容
字段，自定义表和远端必须完全一致。

## Header Custom

TCP header custom 分为 `clients`、`servers` 和 `errors`，每项是动作序列：

```yaml
finalmask:
  tcp:
    - type: header-custom
      settings:
        clients:
          - - type: bytes
              packet: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
              delay: 0
        servers: []
        errors: []
```

动作还可使用 `rand`、`randRange`、`capture`、`reuse` 和递归 `transform`。这是低层
编排接口，packet 形状和变换参数必须与远端实现一致。优先从已验证的双方配置复制，
不要凭猜测组合。

## UDP noise 与 salamander

```yaml
finalmask:
  udp:
    - type: noise
      settings:
        reset: 10-30
        noise:
          - rand: 8-24
            type: bytes
            packet: "00010203"
            delay: 0-5
    - type: salamander
      settings:
        password: replace-me
        packetSize: 512-1200
```

UDP mask 的顺序就是执行顺序。双方类型、顺序、密码和包范围必须一致。

## XDNS、XICMP 与 Realm

```yaml
finalmask:
  udp:
    - type: xdns
      settings:
        domains:
          - dns.example.com
        resolvers:
          - edge+udp://203.0.113.53:53

    - type: xicmp
      settings:
        dgram: true
        ips:
          - 203.0.113.8

    - type: realm
      settings:
        url: https://realm.example.com/connect
        stunServers:
          - stun:stun.example.com:3478
        tlsConfig:
          serverName: realm.example.com
          alpn: [h2]
```

XDNS 旧字段 `domain` 已移除，必须分别使用服务端 `domains` 和客户端 `resolvers`。
两者不能同时为空，resolver 字符串必须包含 `+udp://`。

Realm 的 `tlsConfig` 使用与 XHTTP 相同的强类型 TLS 对象，可配置 CA、固定证书、
版本、曲线、fingerprint 和 ECH。

## QUIC 参数与端口跳跃

```yaml
finalmask:
  quicParams:
    congestion: bbr
    bbrProfile: standard
    brutalUp: 100 mbps
    brutalDown: 500 mbps
    brutalDisableLossCompensation: false
    initStreamReceiveWindow: 8388608
    maxStreamReceiveWindow: 16777216
    initConnectionReceiveWindow: 16777216
    maxConnectionReceiveWindow: 33554432
    maxIdleTimeout: 30
    keepAlivePeriod: 10
    disablePathMTUDiscovery: false
    maxIncomingStreams: 128
    udpHop:
      ports: 20000-30000
      interval: 20-40
```

校验范围：

| 字段 | 约束 |
| --- | --- |
| `congestion` | 空、`brutal`、`force-brutal`、`reno` 或 `bbr` |
| `bbrProfile` | 空、`conservative`、`standard` 或 `aggressive` |
| 非零窗口 | 至少 16384 |
| `maxIdleTimeout` | 非零时 4 到 120 |
| `keepAlivePeriod` | 非零时 2 到 60 |
| `maxIncomingStreams` | 非零时至少 8 |
| `udpHop.interval` | 非零时至少 5 |

`udpHop` 只改变客户端目标端口，不能用于服务端监听。

## 监听端限制

XHTTP 和 REALITY 监听会复用 StreamSettings，但不是所有出站字段都能执行：

- H3 XHTTP 监听不能使用 TCP socket 字段。
- H3 XHTTP 监听不能使用 TCP FinalMask。
- TCP XHTTP 监听不能使用 UDP FinalMask 或 `quicParams`。
- REALITY 监听只能使用 TCP 或 raw 网络。
- REALITY 监听不能使用 UDP FinalMask 或 `quicParams`。
- 客户端专属的 `domainStrategy`、`dialerProxy` 等不能放到监听端。
- `udpHop` 不能放到任何服务端监听。

这类字段会明确报错，不会因为结构能够反序列化就被忽略。

## 选择顺序

调优时按以下顺序逐层增加：

1. 先让节点协议和 TLS 或 REALITY 单独通过。
2. 加入最小 XHTTP，只写 host、path 和 mode。
3. 验证 H1、H2 或 H3 选择正确。
4. 加入独立下载通道并单独验证证书。
5. 加入 XMUX 和会话 placement。
6. 最后加入 socket 专属选项与 FinalMask。

每一步都运行：

```bash
wuther-core check config.yaml
wuther-core explain config.yaml
```

完整字段定义分别见 [XHTTP 字段索引](generated/xhttp.md) 和
[StreamSettings 字段索引](generated/stream.md)。
