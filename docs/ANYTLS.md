# AnyTLS v2 出站

WutherCore 的 AnyTLS 出站按官方协议 v2 和 `sing-anytls` 参考客户端实现，不再使用“每帧末尾拼接若干随机字节”的近似格式。实现基准为：

- `anytls-go` 协议仓库提交 `0c36ca9f0d88bc1af5ddb998e619166913c7445c`；
- `sing-anytls` 提交 `479cb5bd490a2f4b1b6e8cd82b821afb392a94c8`，版本 `v0.0.13`；
- Rust 依赖 `anytls = 0.3.10` 的 `core` feature，用于官方命令、帧和 padding scheme 解析。

官方没有发布 Rust 客户端库。WutherCore 没有直接采用第三方 crate 的 runtime：该 runtime 的会话复用、动态 scheme 和大于 65535 字节的写入行为与上述官方版本存在差异。连接池、TLS 生命周期和状态机因此在 `core-outbound` 中按官方 Go 代码实现，协议基础结构则交给固定版本的依赖库。

## 配置

官方 URI 格式：

```text
anytls://password@server.example.com/?sni=edge.example.com&insecure=0#anytls
```

端口省略时为 `443`。`auth@` 是完整协议密码，不是用户名；百分号编码会在解析时解码。官方 URI 参数 `sni` 与 `insecure=0|1` 均受支持。

手动节点可以使用：

```yaml
nodes:
  - name: anytls
    type: anytls
    server: server.example.com
    port: 443
    password: replace-me
    sni: edge.example.com
    udp: true
    idle-session-check-interval: 30s
    idle-session-timeout: 30s
    min-idle-session: 0
    disable-reuse: false
```

| 字段 | 默认值 | 行为 |
| --- | --- | --- |
| `password` | 必填 | UTF-8 字节先做 SHA-256，再用于认证 |
| `sni` | `server` | TLS 证书名称；IP 地址按 IP 身份校验且不会发送 DNS SNI |
| `insecure` / `allowInsecure` | `false` | 关闭 TLS 证书验证；只建议用于测试 |
| `alpn` | 空 | AnyTLS 不需要应用层 ALPN，不再默认伪造 `h2,http/1.1` |
| `fingerprint` / `fp` | `unsafe` | `unsafe` 在本项目中表示普通 rustls ClientHello，与官方 Go 标准 TLS 客户端对应 |
| `enable-session-resumption` | `false` | TLS 会话恢复开关 |
| `idle-session-check-interval` | `30s` | 空闲池扫描间隔；与官方一致，小于等于 5 秒时回退到 30 秒 |
| `idle-session-timeout` | `30s` | 空闲会话过期时间；小于等于 5 秒时回退到 30 秒 |
| `min-idle-session` | `0` | 清理时至少保留的最新空闲会话数 |
| `disable-reuse` | `false` | 每个代理流结束后关闭其 Session |
| `udp-over-tcp` | 跟随 `udp` | 使用 sing-box UDP-over-TCP v2 |

下划线、短横线和官方 camelCase 形式的会话参数均可解析。密码为空、布尔值非法、duration 非法或 `minIdleSession` 不是非负整数时，节点注册直接失败，不会静默退化。

## 认证与首包

TLS 握手后客户端一次写出：

```text
SHA256(password)[32] || padding0_length_be16 || zero_padding[padding0_length]
```

`padding0` 来自当前 scheme 的 `0=` 项，只取第一个尺寸且不分包。认证后首个 Session 写入严格保持以下次序，并作为 padding 计数器的 packet 1：

```text
cmdSettings(sid=0, "v=2\nclient=WutherCore/<version>\npadding-md5=<md5>")
cmdSYN(sid=1, empty)
cmdPSH(sid=1, SOCKS5 address of target)
```

目标地址不在 `cmdSYN` 中。它是 Stream 的第一段 `cmdPSH` 数据，这一点是旧实现与官方协议不兼容的主要原因之一。

## 会话帧

所有认证后的消息使用：

```text
command:u8 || stream_id:be32 || data_length:be16 || data
```

| ID | 命令 | 客户端行为 |
| ---: | --- | --- |
| 0 | `cmdWaste` | 接收时读取并丢弃；发送 padding 时承载零字节 |
| 1 | `cmdSYN` | 开启 Stream，data 必须为空 |
| 2 | `cmdPSH` | Stream 数据；一次大写入拆为多个不超过 65535 字节的帧，并保持为一个逻辑 TLS Write |
| 3 | `cmdFIN` | 完整关闭 Stream；收到后不回复 FIN；Session 关闭时不逐流发送 FIN |
| 4 | `cmdSettings` | 新 Session 的首个会话帧 |
| 5 | `cmdAlert` | 记录服务端原因并关闭整个 Session |
| 6 | `cmdUpdatePaddingScheme` | 校验后更新这个 AnyTLS Client 对象的 scheme |
| 7 | `cmdSYNACK` | v2 服务端报告目标握手成功或错误 |
| 8 | `cmdHeartRequest` | 立即回复相同 stream ID 的 `cmdHeartResponse` |
| 9 | `cmdHeartResponse` | 接收并确认；官方当前未定义主动心跳调度 |
| 10 | `cmdServerSettings` | 解析 `v`，启用双方都支持的 v2 行为 |

未知命令会完整消费其 data 后忽略，避免破坏后续帧边界。复用 Session 上的 Stream 在双方协商为 v2 后等待 SYNACK；3 秒没有收到会关闭疑似卡死的 Session。带错误文本的 SYNACK 只关闭对应 Stream。

## Padding scheme 与性能

默认 scheme 与官方完全相同：

```text
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
```

它是固定的发送策略，不是“每发一个 AnyTLS 帧都先随机决定是否填充”：

1. packet 0 是认证。
2. packet 1 起按底层 TLS Write 次数计数，而不是按 AnyTLS frame 数计数。
3. 只有 scheme 中当前 packet 的范围需要取样时才生成范围内的尺寸。
4. 到 `stop` 后永久关闭该 Session 的 padding 快路径，普通代理数据不再调用随机数生成。
5. payload 不足目标尺寸时附加一个合法 `cmdWaste` 零填充帧；payload 超过策略列出的尺寸时，剩余数据直接发送。
6. `c` 是检查点：前一个记录已经耗尽 payload 时立即结束本次 Write，不再制造后续纯 padding。

因此随机数成本只出现在连接早期、scheme 明确配置了范围的少数记录中，不在高频稳态发包路径上。固定范围如 `30-30` 和 `9-9` 不需要随机取样。

当前官方参考客户端只对客户端发送方向运行这套 TLS Write 策略。接收方向不维护一个猜测性的 padding 计数器，而是按正常帧格式解析并丢弃 `cmdWaste`。服务端若发送 Waste 也能被正确处理。这避免了旧实现用同一个收发计数器跳过裸字节、最终造成双向流错位的问题。

服务端发现 `padding-md5` 不匹配时用 `cmdUpdatePaddingScheme` 下发原始文本。scheme 存在于连接该服务端的 Client 对象中：后续 Session 的认证 padding0 与 Settings MD5 使用新值；当前活跃 Session 后续的发送记录也与官方 `sing-anytls` 一样从同一共享值读取。更新不会跨 AnyTLS 节点传播。实现接受完整的 `u32 stop` 空间；原始文本受协议 `u16 data length` 约束，单个 Waste payload 也必须能由 `u16` 表示。语法非法或无法形成合法帧的更新只记录警告，不替换现有 scheme。

## 会话复用

AnyTLS 的“复用”不是在同一 Session 上并发塞入任意数量的活跃代理流。官方池策略是：

1. 新请求优先取 sequence 最大的空闲 Session。
2. 没有空闲 Session 时建立新 TLS 连接，sequence 单调递增。
3. Stream 完整结束且 Session 健康时才放回空闲池。
4. 清理任务优先保留最新会话，关闭超过 timeout 的旧会话，同时满足 `minIdleSession`。
5. 复用 Session 上 `cmdSYN` 与目标地址 `cmdPSH` 是两个独立 TLS Write，各自推进 padding packet 计数器。

并发代理请求会在没有空闲 Session 时并行建立新的 Session，而不是错误地共享一个正在使用的 Session。写入由稳定的后台桥接任务驱动，不会在 `poll_write` 返回 Pending 后丢弃 Future。

## UDP-over-TCP v2

UDP 使用官方要求的 sing-box UoT v2：

1. 先建立目标为 `sp.v2.udp-over-tcp.arpa:0` 的 AnyTLS TCP Stream。
2. 写入 `isConnect=1` 和真实目标的 SOCKS5 address。
3. 每个数据报使用 `length_be16 || payload`。

一个关联固定一个目标，向其他目标发送会返回错误。数据报不能超过 65535 字节。接收缓冲区不足时会完整丢弃当前数据报再返回错误，下一帧仍保持对齐。

## 实现检查

协议向量测试覆盖命令编号、认证布局、Settings/SYN/PSH 首包顺序、超过 65535 字节的 PSH 拆分、Waste 补齐、UoT 请求和恶意 scheme 边界。URI 测试覆盖默认 443、百分号编码密码、官方 `insecure` 参数和 IPv6。
