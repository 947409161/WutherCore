# Hysteria 1 / 2 出站协议

WutherCore 的 Hysteria 出站分别按官方 Hysteria 1 `hy1` 分支和 Hysteria
2 协议实现。两版协议只共用 QUIC/TLS、UDP carrier 和拥塞控制基础设施，
不会把 Hysteria 1 映射成 Hysteria 2，也不会使用旧实现中的 MessagePack
近似帧。

实现基准：

- Hysteria 1：[官方 `hy1` 分支提交 `ac56271`](https://github.com/apernet/hysteria/tree/ac56271d030310e2c5f907e1d3329b6ef09b45f0)；
- Hysteria 2：[官方主分支提交 `9aa898c`](https://github.com/apernet/hysteria/tree/9aa898c5bb3a734a620391ae3d101dda36d84bfd)；
- Hysteria 2 线协议：[官方 Protocol 文档](https://v2.hysteria.network/docs/developers/Protocol/)；
- Hysteria 2 URI：[官方 URI Scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/)。

官方项目没有发布可嵌入 Rust 进程的 Hysteria 客户端库。WutherCore 使用
Quinn / quinn-proto 执行 QUIC v1、QUIC Datagram 和拥塞控制接口，使用
h3 / h3-quinn 执行 HTTP/3，使用 rustls 执行 TLS 1.3、证书验证、证书固定
和 ECH。协议帧、会话路由和 Brutal 状态机按上述官方 Go 源码实现。旧的
第三方 `rsteria2` 依赖已经移除，避免一部分字段走本地实现、另一部分字段
停留在未使用对象中的双轨状态。

## 快速配置

Hysteria 2 官方 URI：

```text
hysteria2://完整认证串@example.com:443/?sni=edge.example&obfs=salamander&obfs-password=secret&insecure=0#HY2
```

端口可以省略，默认是 `443`。userinfo 整体是认证串：
`hysteria2://alice:password@...` 会把 `alice:password` 原样用作
`Hysteria-Auth`，不会把它错误拆成用户名和密码。百分号编码会先解码。

官方多端口写法也会变成实际端口跳跃计划：

```text
hy2://auth@example.com:2000,3000-3002?hopInterval=8s
```

Hysteria 1 必须明确提供认证和非零上下行带宽。兼容的裸整数 `up` / `down`
按旧版 `up_mbps` / `down_mbps` 处理，换算使用十进制
`Mbps × 125000 B/s`。显式字符串语法与官方 `stringToBps` 一致：只能使用
整数和 `K/M/G/T` 二进制前缀，末尾小写 `b` 表示 bit、大写 `B` 表示
byte，例如 `100 Mbps` 是 `100 × 2^20 / 8 B/s`，`100 MBps` 是
`100 × 2^20 B/s`；小数会被拒绝：

```text
hysteria://auth@example.com:443?up=100&down=200&obfs=xplus-password&sni=edge.example
```

Hysteria 2 可以省略 `up` / `down`。省略上传带宽表示使用自适应拥塞控制，
不是为了绕过校验而写入的占位 0；省略下载带宽会按官方协议发送
`Hysteria-CC-RX: 0`，其含义是接收不限速。官方结构化配置中的整数是
`B/s`；带单位字符串只能使用整数和十进制 SI 前缀，统一表示 bit/s，例如
`100 Mbps = 12,500,000 B/s`。服务端响应中的数字 `0` 与字符串 `auto`
也保持不同语义：数字 `0` 保持本地 Brutal 速率，`auto` 切换到自适应
控制。

两代默认 QUIC 参数也分别保留，不会因为共用执行器而串版：

| 参数 | Hysteria 1 | Hysteria 2 |
| --- | ---: | ---: |
| stream receive window | 16 MiB | 8 MiB |
| connection receive window | 40 MiB | 20 MiB |
| idle timeout | 20 秒 | 30 秒 |
| keepalive | `idle × 2 / 5` | 10 秒 |
| 默认 hop interval | 10 秒 | 30 秒 |
| 最小 hop interval | 8 秒 | 5 秒 |

## Hysteria 1 线协议

所有整数都是大端。布尔字段只能是 `0` 或 `1`，其他值按协议错误处理。

### 控制流

连接建立后，客户端打开第一个双向 QUIC stream：

| 顺序 | 字段 | 编码 |
| --- | --- | --- |
| 1 | ProtocolVersion | `u8`，固定为 `3` |
| 2 | SendBPS | `u64`，客户端上传字节/秒 |
| 3 | RecvBPS | `u64`，客户端下载字节/秒 |
| 4 | AuthLen | `u16` |
| 5 | Auth | `AuthLen` 字节 |

服务端响应：

| 顺序 | 字段 | 编码 |
| --- | --- | --- |
| 1 | OK | `u8 bool` |
| 2 | SendBPS | `u64` |
| 3 | RecvBPS | `u64` |
| 4 | MessageLen | `u16` |
| 5 | Message | UTF-8 |

认证成功后，服务端 `RecvBPS` 会实际更新客户端 Brutal 发送速率；任一协商
带宽为 0 都会中止连接，不会继续运行一个无意义的控制器。

### TCP 与 UDP 会话请求

每次请求打开一个双向 stream：

```text
UDP:u8-bool | HostLen:u16 | Host | Port:u16
```

服务端响应：

```text
OK:u8-bool | UDPSessionID:u32 | MessageLen:u16 | Message
```

TCP 请求使用真实目标 Host/Port，成功后 stream 余下字节就是代理数据。
`fastOpen=true` 时响应验证延迟到第一次读取，允许调用方先写早期数据；关闭
时 `dial_tcp` 会先完整验证响应。UDP 请求使用 `UDP=1, Host="", Port=0`，
并把服务端返回的 `UDPSessionID` 注册到 datagram 路由器。官方服务端从
`0` 开始分配该字段，因此 `0` 是第一个真实会话 ID，不是占位值。该请求
stream 会保持到 UDP association 关闭。

### UDP Datagram

```text
SessionID:u32
HostLen:u16 | Host
Port:u16
MsgID:u16
FragID:u8 | FragCount:u8
DataLen:u16 | Data
```

未分片包必须使用 `FragCount=1`。分片包必须使用非零随机 `MsgID`，
`FragID` 从 0 递增；接收端按 `SessionID` 分发，再按 `MsgID`、分片数量和
顺序重组。重复分片被丢弃，总重组数据受 `u16` 协议上限约束。发送时先尝试
原始 datagram，只有 Quinn 返回 `TooLarge` 才按当前路径 datagram 上限拆分。

### XPlus

Hysteria 1 的 `obfs` 是官方 XPlus，不是 Hysteria 2 Salamander：

```text
salt[16] | payload XOR repeat(SHA256(password || salt))
```

每个底层 QUIC packet 使用独立 16 字节安全随机 salt。短于或等于 16 字节
的入站包无法包含 payload，会被丢弃。XPlus 运行在 QUIC packet carrier，
不会错误地对 TCP/UDP 代理 payload 二次处理。

## Hysteria 2 线协议

### HTTP/3 认证

客户端发送：

```http
POST https://hysteria/auth
Hysteria-Auth: <完整认证串>
Hysteria-CC-RX: <客户端下载 B/s>
Hysteria-Padding: <256..2047 字节随机 ASCII>
```

认证成功状态码固定为 `233`，不是 HTTP `200`。客户端要求响应同时包含：

- `Hysteria-UDP`：合法布尔值，决定服务端是否开放 UDP；
- `Hysteria-CC-RX`：无符号整数或精确字符串 `auto`。

认证 padding 只在建连认证时生成，不在每个数据包上重复生成。

### TCP

请求：

```text
Type:QUIC-varint(0x401)
AddressLen:QUIC-varint | "host:port"
PaddingLen:QUIC-varint | Padding[64..511]
```

响应：

```text
Status:u8
MessageLen:QUIC-varint | Message
PaddingLen:QUIC-varint | Padding
```

`Status=0` 表示成功。地址和消息最大 2048 字节，响应 padding 最大 4096
字节。实现会消费完整响应 padding，并把同一次 QUIC read 中已经到达的代理
payload 保留下来交给调用方。`fastOpen` 与 Hysteria 1 一样只改变响应验证
时机，不省略验证。

### UDP

```text
SessionID:u32
PacketID:u16
FragID:u8 | FragCount:u8
AddressLen:QUIC-varint | "host:port"
Data
```

UDP association 使用客户端原子分配的非零 SessionID。数据先按 SessionID
路由，再按 PacketID 重组；单个逻辑 UDP payload 上限 4096 字节。发送先
尝试未分片 datagram，超过路径上限时才分片。接收循环是每个 QUIC connection
唯一的 datagram reader，避免多个 association 竞争并误取彼此的数据。

### Salamander、Gecko 与端口跳跃

- `obfs=salamander` 的 wire format 是
  `salt[8] | payload XOR repeat(BLAKE2b-256(password || salt))`；密码至少
  4 字节，每个底层 packet 都生成新的 8 字节 salt；
- `obfs=gecko` 对 QUIC short-header packet 只套 Salamander；对
  long-header packet 随机拆成 2 到 8 个 Gecko frame，每帧携带
  message/chunk/padding 元数据并在外层套 Salamander。packet 范围默认
  `512..1200`，最大不能超过 2048，乱序重组表有 8 秒 TTL 和单一服务端
  来源 8 条并发上限；
- 多端口 authority 或 `hopPorts` 编译为去重后的端口列表，
  H1/H2 的最小 `hopInterval` 分别是 8/5 秒；
- 协议 obfs 与 `finalmask` 中另一个 Salamander/Gecko 会明确报冲突；
  端口跳跃与需要固定 carrier endpoint 的 Realm/XICMP 也会明确报冲突。

这些变换作用于双向底层 QUIC packet，因此认证、TCP stream 和 UDP datagram
都会经过相同 carrier；不是只发送配置字段而不执行。

## Brutal

Brutal 由两部分共同执行：Quinn transport 中的 congestion controller
负责在途窗口、RTT 和 ACK/loss 状态机；最底层异步 packet worker 运行官方
独立 token-bucket pacer。Hysteria 认证前使用 BBR 完成 QUIC 建连，只有
收到数值型速率协商结果后才原子切换到 Brutal；每条新 QUIC 连接都有独立
采样状态和令牌桶。

| 行为 | Hysteria 1 | Hysteria 2 |
| --- | ---: | ---: |
| ACK/loss 秒槽 | 4 | 5 |
| 开始补偿的最小样本 | 50 | 50 |
| 最低 ACK rate | 0.8 | 0.8 |
| congestion window | `BPS × SRTT × 1.5 / ACK rate` | `BPS × SRTT × 2 / ACK rate` |
| 初始 window | 10240 字节 | 10240 字节 |
| pacer 最大 burst | `max(BPS/ACK × 2ms, 10×MTU)` | `max(BPS/ACK × 4ms, 10×MTU)` |
| pacer 最小等待 | 1 ms | 1 ms |
| `disableLossCompensation` | 不支持 | 支持，ACK rate 固定为 1 |

ACK 按确认的 packet 计数，loss 按 Quinn 报告的丢失字节和当前 MTU 向上折算；
ECN-only 事件不会伪造一个丢包。pacer 使用补偿后的
`truncate(float64(BPS) / ACK rate)`，补充令牌、burst 上限、MTU 门槛和
向上取整的等待时间都在真实发包路径执行，并非只填写 metrics。Brutal 不
执行 Reno/Cubic 式乘法退避。Hysteria 2 的 `auto` 响应会保持/切回 Quinn
BBR；`reno` 配置会安装 NewReno。

## 配置字段消费矩阵

| 字段 | 实际运行时用途 |
| --- | --- |
| `auth` / `auth-str` / URI userinfo | H1 ClientHello auth 或 H2 `Hysteria-Auth` |
| `up` / `down` | H1 ClientHello + Brutal；H2 auth CC-RX + Brutal/自适应选择 |
| `sni`、`insecure`、`alpn` | rustls SNI、证书验证和 ALPN；H2 ALPN 固定为 `h3` |
| `pinSHA256` / `pinnedPeerCertSha256` | 叶证书或中间 CA SHA-256 固定 |
| `ech` / `echConfigList` | rustls ECHConfigList；DNS URL 会在连接前解析 |
| `obfs` / `obfs-password` | H1 XPlus；H2 Salamander/Gecko packet carrier |
| Gecko min/max packet size | H2 Gecko padding 范围校验与 packet 编码 |
| `fastOpen` | TCP 响应验证时机 |
| `udp` | capability、H2 服务端能力检查和 UDP router 建立 |
| `congestion` / `bbrProfile` | BBR、NewReno、Brutal factory 选择 |
| QUIC receive windows | Quinn stream/connection 初始与最大接收窗口 |
| H1 `handshake_timeout` | 实际包裹 Quinn connecting future；超时返回 `TimedOut` |
| idle timeout / keepalive | 按代际默认值或显式值安装 Quinn transport timer |
| PMTU disable | 关闭 Quinn MTU discovery |
| hop ports / interval | 双向 QUIC UDP carrier 的定时端口轮换 |
| `disableLossCompensation` | H2 Brutal ACK-rate 补偿开关 |

Hysteria 1 的 `recv_window_conn` 同时设置初始/最大 stream window，
`recv_window` 同时设置初始/最大 connection window；这两个旧版名字不会
再被反向映射。缺少认证、上传带宽或下载带宽会在注册阶段失败。Hysteria 2
官方 `bandwidth`、`congestion`、`obfs`、`quic.sockopts`、`tls` 和
`transport.udp` 嵌套对象会展开到上述真实执行字段；未知子字段、字段冲突、
孤立 `obfs-password`、非法 Gecko 范围以及无法由当前平台执行的
`fdControlUnixSocket` 都会报配置错误。

官方 Hysteria 应用还包含独立于 H1/H2 线协议的 carrier/启动器功能。
H1 `faketcp`/`wechat-video` 需要 raw packet backend；H2 `realm://` 需要
STUN、打洞和端口映射启动流程。它们不能退化成普通 UDP 后假装成功：当前
协议注册器会对不具备完整 backend 的官方应用模式 fail closed；已经配置
在 `streamSettings.finalmask` 的 Realm 执行器仍会真实运行。`lazy=false`
同样会因 WutherCore 的按需出站生命周期不兼容而明确拒绝。

## 验证范围

固定向量测试覆盖 Hysteria 1 ClientHello、TCP/UDP 请求、UDP datagram 和
XPlus（包括官方首个 UDP SessionID `0`），Hysteria 2 TCP 请求/响应、官方 UDP golden vector、CC-RX 的
`0`/`auto` 区分，以及 Salamander/Gecko 的独立配置。URI 测试覆盖默认
443、完整 userinfo 认证和多端口 authority；配置测试覆盖两代不同的带宽
单位、窗口方向、timer/hop 下限及 H2 嵌套对象。workspace CI 还会编译
所有 target，防止能力字段与真实 `dial_udp` / packet pacing 路径再次
脱节。
