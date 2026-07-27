# Young v1 协议规范与部署指南

Young 是 WutherCore 自主实现的代理协议，不复用 VLESS、REALITY、Hysteria
等协议的握手或内层帧。Young v1 的承载栈为：

```text
UDP
└── Mozilla Neqo QUIC v1 + NSS/TLS 1.3
    └── HTTP/3（ALPN: h3）
        └── WebTransport
            ├── 双向流：Young TCP
            └── Datagram：Young UDP
```

客户端和服务端直接使用 Mozilla Neqo。Neqo 固定到提交
`76673b127251c90ad6250de7a0a7400ddd4661f1`，`nss-rs` 固定到
`b7cfa30c8a526167cf6bd653b4a6d4f8549280eb`，以保证构建可复现。Neqo
通过 `nss-rs` 使用 Mozilla NSS；WutherCore 不包含手写 NSS FFI，但构建和运行
仍需要 NSS 原生库。

本文中的所有多字节整数均使用网络字节序。`C2S` 表示客户端到服务端，`S2C`
表示服务端到客户端。

## 1. 设计目标与边界

- 使用真实 QUIC、HTTP/3 和 WebTransport 状态机，不构造“类似 QUIC”的私有外层。
- 一个已认证会话复用多个 TCP 流和 UDP association，摊薄握手成本。
- 预共享密钥不直接充当流量密钥；内层会话密钥绑定 TLS exporter 和随机 nonce。
- 抵抗无凭据主动探测、认证重放、路径枚举和内层报文篡改。
- 未认证请求表现为普通 HTTP/3 响应，不泄露 Young 版本和认证状态。
- TCP 支持双向传输和半关闭；UDP 支持 `1..=65507` 字节报文、分片与乱序重组。
- 新版双方协商后，FlowOpen、TCP 应用数据和 UDP 分片都实施双向 padding。
- 高频发包路径不调用操作系统 RNG，也不争用全局随机数锁。
- padding 改变长度分布，但不实现恒定速率、时序整形、cover traffic 或 ECH。

## 2. 密钥、证书与派生

### 2.1 用户密钥

每个用户密钥必须是 32 个 CSPRNG 随机字节，以无填充 base64url 表示：

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
```

`key_id = SHA-256(key)[0..8]`，仅用于服务端从 key ring 选择密钥。日志和
`Debug` 输出只显示 key id。服务端可以同时保留新旧密钥以完成无中断轮换。

### 2.2 证书固定

客户端必须配置服务端叶证书 DER 的 SHA-256 摘要，支持 64 位十六进制或无填充
base64url。协议没有跳过校验的开关。

```bash
openssl x509 -in cert.pem -outform DER | openssl dgst -sha256
```

### 2.3 会话密钥

认证成功后，双方从 WebTransport 会话取得 TLS exporter，并计算：

```text
session_key = HMAC-SHA256(
  user_key,
  "young/exporter/v1" || tls_exporter || client_nonce
)
```

因此，截获的 Authorization 不能脱离其 TLS 会话复用为内层流量密钥。

## 3. WebTransport 会话认证

客户端向每日轮换路径发送标准 WebTransport CONNECT：

```text
:method = CONNECT
:protocol = webtransport
:scheme = https
:authority = <configured authority>
:path = <base path>/<daily token>
authorization = Bearer <Young authorization>
```

每日路径为：

```text
day = floor(unix_seconds / 86400)
daily_token = base64url(HMAC-SHA256(key, "young/path/v1" || day)[0..9])
path = trim_end_slash(base_path) || "/" || daily_token
```

服务端接受当前日期及前后各一天的路径，以容忍日期边界。

Authorization 解码后为：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| Version | 1 | `0x01` |
| Key ID | 8 | `SHA-256(key)[0..8]` |
| Timestamp | 8 | UNIX 秒 |
| Client nonce | 16 | CSPRNG 随机数 |
| Capabilities | 4 | 能力位集合 |
| Tag | 32 | HMAC-SHA-256 |

Tag 覆盖：

```text
"young/session/v1" || authority || path || fields_before_tag
```

能力位为：

| 位 | 值 | 含义 |
| --- | ---: | --- |
| TCP | `0x00000001` | 支持 TCP flow |
| UDP | `0x00000002` | 支持 UDP association |
| Padding scheme v1 | `0x00000004` | 支持旧式单向 FlowOpen 长度表 |
| Bidirectional padding | `0x00000008` | 支持 scheme v2、双向 TCP/UDP padding |

服务端按时间窗验证时间戳，并将 `(key_id, client_nonce)` 原子写入有界重放缓存。
同一个认证值只能成功一次。服务端通过 `sec-young-accept` 返回：

```text
base64url(
  HMAC-SHA256(key, "young/server-accept/v1" || client_nonce)
)
```

客户端必须先验证该证明和 padding scheme，之后才能开放代理流。

## 4. 每会话双向 padding scheme

### 4.1 生成

服务端为每个认证成功的 WebTransport 会话生成一份 scheme。配置约束为：

```text
1 <= paddingMin <= paddingMax <= 4096
1 <= paddingSchemeLength <= 256
```

服务端只在会话建立的低频路径调用一次线程本地 CSPRNG，取得 256-bit seed，再由
`rand_chacha::ChaCha8Rng` 连续生成 C2S、S2C 两张等长但独立的表。默认每张表
64 项，每项 `64..=512`。64 项使用 `smallvec::SmallVec` 的内联存储。

scheme 生命周期等于 WebTransport 会话。重连会生成新 seed、新 C2S 表和新 S2C
表。当前版本不在会话中途更新，避免更新帧丢失或乱序导致状态分叉。

### 4.2 scheme v2 编码

声明 `0x00000008` 的客户端收到 `sec-young-padding`，其无填充 base64url
解码布局为：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| Scheme version | 1 | `0x02` |
| Entry count | 2 | `1..=256` |
| C2S lengths | `count * 2` | 每项 `1..=4096` |
| S2C lengths | `count * 2` | 每项 `1..=4096` |
| Tag | 32 | HMAC-SHA-256 |

Tag 覆盖：

```text
"young/padding-scheme/v2" || client_nonce || all_fields_before_tag
```

客户端必须验证版本、总长度、条目数量、每个非零长度和 Tag。任何失败都终止会话，
不会静默改用未认证的默认表。

scheme v1 仅含 C2S 表，版本为 `0x01`，HMAC 域为
`"young/padding-scheme/v1"`。它只用于和已经发布的旧实现互操作，不启用后续
TCP/UDP 数据 padding。

### 4.3 padding 字节生成

长度表只决定长度，padding 内容不是零填充。发送端使用 `blake3` 的 keyed XOF：

```text
padding = BLAKE3-keyed-XOF(
  key = session_key,
  input = domain || fixed_width_context
)[0..padding_length]
```

域和上下文为：

| 用途 | Domain | Context |
| --- | --- | --- |
| FlowOpen | `young/flow-padding/v1` | `flow_id:u64` |
| TCP C2S | `young/tcp-padding/c2s/v1` | `flow_id:u64 || sequence:u64` |
| TCP S2C | `young/tcp-padding/s2c/v1` | `flow_id:u64 || sequence:u64` |
| UDP C2S | `young/udp-padding/c2s/v1` | `association_id:u64 || packet_id:u32 || fragment_index:u16` |
| UDP S2C | `young/udp-padding/s2c/v1` | `association_id:u64 || packet_id:u32 || fragment_index:u16` |

接收端必须用相同上下文重算并比较全部 padding 字节。这里的“确定性”只针对同一
会话密钥和同一上下文；会话密钥随 TLS 会话与 nonce 改变，外部观察者不能预知
padding 明文。实现不会为每个帧调用 RNG、系统调用或共享锁。

## 5. FlowOpen 与 FlowResponse

每条 TCP flow 或 UDP association 使用一条 WebTransport 双向流。第一个帧为
FlowOpen：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| Magic | 2 | `YF` |
| Version | 1 | `0x01` |
| Kind | 1 | `1=TCP`，`2=UDP association` |
| Flow ID | 8 | 会话内非零标识 |
| Target port | 2 | 目标端口 |
| Address type | 1 | `1=IPv4`，`2=域名`，`3=IPv6` |
| Address | 可变 | IPv4 4 字节、IPv6 16 字节，或 `u8 length + UTF-8` |
| Padding length | 2 | v2 中必须为 scheme 指定的 `1..=4096` |
| Padding | 可变 | BLAKE3 keyed XOF 输出 |
| Tag | 16 | 截断 HMAC-SHA-256 |

Tag 覆盖：

```text
"young/flow-open/v1" || all_fields_before_tag
```

在 scheme v2 中：

```text
padding_length = C2S[flow_id mod entry_count]
```

服务端同时验证长度命中表、确定性 padding 内容和 HMAC。由于索引由 `flow_id`
直接决定，并发打开的 QUIC stream 即使到达次序不同也不会让双方计数器失步。
scheme v1 兼容路径仍按旧客户端的顺序游标选择长度，服务端只执行原有 HMAC 和
边界验证。

服务端响应固定长度 FlowResponse：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| Magic | 2 | `YR` |
| Version | 1 | `0x01` |
| Status | 1 | 状态码 |
| Flow ID | 8 | 对应请求 |
| Tag | 16 | 截断 HMAC-SHA-256 |

状态码为 `0=成功`、`1=请求错误`、`2=未授权`、`3=连接失败`、
`4=不支持`、`5=资源上限`。

## 6. TCP 双向数据帧

scheme v2 会话中的 TCP 字节流不能直接裸传。FlowResponse 成功后，C2S 和 S2C
各自编码为连续的 Young data frame：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| Magic | 2 | `YP` |
| Version | 1 | `0x01` |
| Flags | 1 | 必须为 `0` |
| Sequence | 8 | 每方向从 0 开始，严格连续 |
| Payload length | 2 | `1..=32768` |
| Padding length | 2 | 必须等于当前方向表项 |
| Payload | 可变 | TCP 应用数据 |
| Padding | 可变 | 对应方向的 BLAKE3 keyed XOF 输出 |

每个方向具有独立的 sequence 和表游标。初始游标为：

```text
C2S data cursor = (flow_id + 1) mod entry_count
S2C data cursor = flow_id mod entry_count
```

C2S 加一是为了避免 FlowOpen 与紧随其后的首个 C2S data frame 重复使用同一
表项。每成功解析一帧，sequence 加一，游标加一并在表尾归零。应用数据超过
32768 字节时拆成多帧。解析器允许 QUIC 任意拆分或合并读取；FIN 到达时仍有
不完整帧属于协议错误并重置该 flow。

TCP data frame 不重复添加 HMAC。QUIC AEAD 已认证 stream 身份、顺序和内容；
再为每个 TCP frame 计算 HMAC 只会重复散列。Young 仍严格检查 magic、flags、
sequence、长度、scheme 表项和确定性 padding 内容。方向域不同，因此即使 C2S
和 S2C 表项长度偶然相同，跨方向帧也不能通过 padding 验证。

只有明确协商到 scheme v1 或没有 scheme 的旧对端才使用旧式裸 TCP 字节流。
新版客户端与新版服务端成功协商 `0x00000008` 后，两方向都必须使用 `YP`，
不存在“字段填 0但仍裸传”的可选分支。

WebTransport 两个发送方向分别映射 TCP 两个发送方向，FIN 独立传播，保留
“发送半关闭后继续接收”的语义。

## 7. UDP 双向 padded datagram

UDP association 先完成 FlowOpen/FlowResponse。scheme v2 会话中的每份 UDP
报文使用 WebTransport Datagram，超过当前 QUIC datagram 上限时分片。padded
分片格式为：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| Magic | 2 | `YD` |
| Version | 1 | `0x01` |
| Flags | 1 | padded 格式必须为 `1` |
| Association ID | 8 | 对应 UDP association |
| Packet ID | 4 | 每份原始 UDP 报文递增 |
| Fragment index | 2 | 从 0 开始 |
| Fragment count | 2 | `1..=256` |
| Total length | 2 | 原始 UDP 报文长度 |
| Payload length | 2 | 当前分片有效数据长度 |
| Padding length | 2 | 当前分片 padding 长度 |
| Payload | 可变 | 当前分片数据 |
| Padding | 可变 | 对应方向的 BLAKE3 keyed XOF 输出 |
| Tag | 16 | 截断 HMAC-SHA-256 |

表索引为：

```text
index = (association_id + packet_id + fragment_index) mod entry_count
requested_padding = direction_table[index]
```

若 QUIC datagram 上限不足以容纳请求长度，发送端将 padding 截短，但必须至少为
payload 留一个字节。因此接收端要求
`0 < actual_padding <= requested_padding`；默认配置和通常的 QUIC datagram
上限下不会发生截短。padding 和 payload 都位于 HMAC 覆盖范围。

方向 HMAC 域为：

```text
C2S: "young/udp-fragment/c2s/v2"
S2C: "young/udp-fragment/s2c/v2"
```

接收顺序为：验证方向 HMAC、验证所有长度和数量边界、验证 scheme 与确定性
padding、最后进入重组缓存。重组键为 `(association_id, packet_id)`。同一报文
的 total length 或 fragment count 不一致时丢弃整份报文。重组缓存最多保留
256 份报文，超时 10 秒，每份最多 256 个分片，未知 association 不进入缓存。

旧式 UDP 格式的 Flags 为 `0`，没有 payload length 和 padding length，使用
`"young/udp-fragment/v1"` HMAC 域。它仅用于明确协商出的旧对端路径。

## 8. 状态机、失败处理与兼容性

### 8.1 新版会话

```text
CONNECT + capability 0x08
  -> verify sec-young-accept
  -> verify scheme v2
  -> derive session_key
  -> FlowOpen（校验表项、XOF、HMAC）
  -> FlowResponse
  -> TCP: both directions YP frames
     UDP: both directions YD flags=1 fragments
```

非法 TCP frame 会重置该 flow；FIN 前截断帧同样重置。非法 UDP datagram 被丢弃，
不会终止整个 server worker。scheme 认证失败发生在开放 flow 之前，会终止会话。

### 8.2 兼容矩阵

| 客户端 | 服务端 | scheme | TCP/UDP 数据 |
| --- | --- | --- | --- |
| 新版（bit 8） | 新版 | v2 双向表 | 强制双向 padded 格式 |
| 新版 | 仅支持 bit 4 | v1 C2S 表 | 旧式 FlowOpen + 裸 TCP/旧 UDP |
| 仅支持 bit 4 | 新版 | v1 C2S 表 | 旧式 FlowOpen + 裸 TCP/旧 UDP |
| 不支持 scheme | 新版 | 不下发 | 原始兼容路径 |

兼容分支由认证过的能力位和 QUIC 加密响应头决定。新版双方不能在 v2 会话中逐流
降级；收到裸 TCP 或 Flags=0 UDP 会被当作协议错误。

## 9. 性能模型

Young 将随机数工作从高频数据路径移到会话建立路径：

- 每会话仅一次线程本地 CSPRNG 取种；
- `ChaCha8Rng` 一次展开两张固定表；
- 每个 flow、frame 或 fragment 只做表读取、游标递增和固定宽度上下文构造；
- padding 内容由优化过的 `blake3` keyed XOF 批量填充，不调用 OS RNG；
- TCP 以最多 32768 字节 payload 为单位分帧，避免对很小的 socket read 强制
  逐字节随机操作；
- UDP 在编码前结合 datagram 上限计算 payload/padding 分配，不生成随后丢弃的
  padding；
- `BytesMut` 保留跨 QUIC read 的不完整帧，只在完整帧后推进缓冲区；
- 每流待发送 wire buffer 上限为 1 MiB，避免 padding 放大导致无界排队。

代价也必须明确：

- 每个 v2 TCP frame 增加 16 字节头和一个表项长度的 padding；
- 每个 v2 UDP fragment 增加 4 字节长度字段、16 字节 Tag 和 padding；
- 接收端重算 XOF，以拒绝未实际生成或错误方向的 padding；
- padding 范围设置过大会直接增加带宽、分片数、CPU 和排队压力。

默认 `64..=512`、表长 64 是带宽与长度扰动的折中，不保证适合所有链路。部署者
应以吞吐、P99 延迟、QUIC 丢包率和流量分类效果共同做基准，而不是只增大 padding。

## 10. TIT 缓解意义与限制

TLS-in-TLS（TIT）流量可能暴露内层 TLS record 长度和方向切换的统计关系。v2
padding 的实际作用是：

- FlowOpen 不再具有固定长度；
- TCP 两方向的每个 Young frame 使用独立表，改变内层 write 到外层 QUIC
  payload 的长度映射；
- UDP 两方向和每个分片同样扰动，避免只保护 TCP 或只保护请求方向；
- 表随会话轮换，不能用一张全局固定表长期积累模板；
- 内容由秘密会话密钥派生，避免零串或固定字节成为实现指纹；
- 高频路径无需反复“摇随机数”，降低为抗分析特性付出的锁竞争和系统调用成本。

它不能隐藏总字节数、连接持续时间、包时序、上下行比例、QUIC 本身或目标 IP。
周期表也不是概率上完美的流量整形。因此该机制是对长度相关 TIT 特征的工程缓解，
不是“彻底解决 TIT”的声明。若威胁模型要求抵抗长期相关性分析，还需要独立设计
定时发送、流量整形、cover traffic 和部署侧轮换；这些不属于 Young v1。

## 11. 主动探测与资源防护

- Young 认证头、轮换路径、目标地址和内层帧均位于 QUIC 加密层内。
- 每日路径、随机 nonce、时间窗和有界重放缓存消除长期固定入口和认证重放。
- 证书 SHA-256 固定与 `sec-young-accept` 同时认证服务端。
- 无效认证、错误路径和普通请求返回可配置的普通网页；认证前不连接任意目标。
- scheme 绑定 `client_nonce` 和用户密钥，HTTP/3 中间设备不能剥离或替换。
- 会话、流、待发送队列、报文、分片和重组缓存均有硬上限。
- 流结束或重置时取消对应 relay task，降低慢连接资源占用。

能够整体阻断 UDP、QUIC 或服务端 IP 的网络仍可中断 Young。Young v1 不宣称具备
ECH、域前置或 TCP fallback。

## 12. 服务端配置

NSS 数据库必须包含 `authority` 对应的证书和私钥。一个进程只能初始化一份 NSS
数据库，因此同一配置中的 Young listener 必须使用相同 `nssDatabase`。

```bash
mkdir -p data/nss
certutil -N -d sql:data/nss
pk12util -i server.p12 -d sql:data/nss
certutil -L -d sql:data/nss
```

```yaml
version: 1
profile: server

listen:
  young:
    - host: 0.0.0.0
      port: 443
      nssDatabase: data/nss
      certificateNickname: young.example.com
      authority: young.example.com
      path: /assets
      users:
        - REPLACE_WITH_32_BYTE_BASE64URL_KEY
      clockSkew: 2m
      idleTimeout: 5m
      maxStreams: 1024
      maxSessions: 4096
      maxFlowsPerSession: 256
      paddingMin: 64
      paddingMax: 512
      paddingSchemeLength: 64
      decoyStatus: 404
      decoyBody: "<!doctype html><title>Not Found</title>"

route:
  preset: direct
```

`wuther-core check` 会验证密钥、NSS 数据库一致性、路径、状态码、资源上限和
padding 约束。`paddingMin: 0` 会被拒绝，因为 v2 不允许以零长度条目伪装成
“已实现 padding”。

## 13. 客户端 URI

```text
young://<base64url-key>@<server-ip-or-host>:443\
?security=tls\
&sni=young.example.com\
&authority=young.example.com\
&path=%2Fassets\
&pin-sha256=<leaf-certificate-sha256-hex>\
&padding-min=64\
&padding-max=512\
&idle-secs=300\
&max-streams=1024\
#Young
```

必填项是 32 字节 base64url key、服务器地址、端口、`security=tls`、SNI 和
`pin-sha256`。`authority` 默认等于 SNI，`path` 默认 `/assets`。客户端的
`padding-min/max` 只供旧服务端无 scheme 时生成一次本地兼容表；v2 成功协商后
始终使用服务端认证过的双向表。

## 14. 构建与验证

Linux（Debian/Ubuntu）：

```bash
sudo apt-get install clang gyp mercurial ninja-build pkg-config
cargo build --release -p wuther-core
```

若系统 NSS 低于 `3.121`，不要依赖旧版 `libnss3-dev`；`nss-rs` 会获取并构建
满足要求的 NSS/NSPR。若 `pkg-config --modversion nss` 已为 `3.121` 或更高，
可使用发行版的 `libnss3-dev` 和 `libnspr4-dev`。

Windows 需要 NSS/NSPR、Clang/libclang 和对应构建环境，推荐 MozillaBuild。
纯 codec 测试不需要 NSS：

```bash
cargo test -p core-young --no-default-features --lib
```

真实 Neqo/WebTransport 互操作测试需要 NSS：

```bash
cargo test -p core-young --features firefox-stack --test neqo_roundtrip
```

测试覆盖 scheme v1/v2 认证、非零确定性 padding、错误方向和篡改拒绝、TCP
跨任意 read 边界的多帧拆装、双向大 payload、UDP 双向 padding、分片、乱序重组，
以及错误用户密钥拒绝后服务端继续可用。

## 15. 实现状态与上游边界

Young v1 已接入配置解析、运行计划、内核 listener、出站注册、TCP、UDP、半关闭、
证书固定、重放防护、伪装响应、每会话双向 padding scheme、TCP/UDP 双向 padded
数据格式和真实 Neqo 互操作测试。

Mozilla 仍将 Neqo 服务端能力标记为实验性。部署前应进行容量、升级和异常网络
回归，不应将上游实验性服务端视为无风险的长期兼容承诺。

参考：

- [Mozilla Neqo](https://github.com/mozilla/neqo)
- [Firefox HTTP/3 文档](https://firefox-source-docs.mozilla.org/networking/http/http3.html)
- [Firefox Networking / Necko 术语](https://firefox-source-docs.mozilla.org/networking/necko_lingo.html)
