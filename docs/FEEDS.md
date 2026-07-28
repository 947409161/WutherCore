# 自由订阅与 Mihomo 代理提供者

WutherCore 的 `feeds` 可以直接读取 HTTP、HTTPS、`file://`、本地文件和内联节点。订阅体系以 WutherCore 原生节点模型为主，同时兼容 Mihomo YAML、SIP008、URI 列表及其 Base64 包装。格式未指定时会从正文结构、URI scheme 和节点字段自动探测。

## 配置

```yaml
feeds:
  airport:
    url: https://provider.example/subscription
    every: 6h
    size-limit: 8388608
    header:
      User-Agent: Mihomo/1.19
      X-Age-Public-Key:
        - age1example
    age-secret-key: AGE-SECRET-KEY-1EXAMPLE
    filter: "^(香港|日本)"
    exclude-filter: "到期`剩余流量"
    exclude-type: "direct|reject"
    override:
      udp: true
      tfo: true
      additional-prefix: "机场 "
      clientId: sing-anytls/0.0.13
```

`header` 的值既可以是一个字符串，也可以是字符串列表。`size-limit` 的单位是字节；`0` 使用 WutherCore 的全局 64 MiB 安全上限。`filter` 与 `exclude-filter` 支持回顾和前瞻等扩展正则语法，反引号分隔多条表达式。`exclude-type` 使用竖线分隔协议名。

内联提供者可以直接写原生节点，`nodes`、`outbounds` 和兼容字段 `payload` 等价：

```yaml
feeds:
  local:
    nodes:
      - name: DIRECT
        type: direct
      - name: BLOCK
        type: reject
```

Mihomo `type: file` 可以写成本地路径或 `file://` URL。`migrate` 会把 Mihomo 的 HTTP、文件和内联 proxy-provider 转换为对应的 `feeds`。

## WutherCore 原生订阅

原生订阅正文可以使用 YAML 或 JSON。根节点支持 `nodes`、`outbounds`、节点数组和单个节点；`nodes` 既可以是数组，也可以是“节点名到节点配置”的映射。

紧凑写法适合自行生成订阅：

```yaml
version: 1
nodes:
  - name: Young 香港
    type: young
    server: young.example.com
    port: 443
    key: "base64url-encoded-32-byte-key"
    sni: young.example.com
    authority: young.example.com
    path: /assets
    pin-sha256: "64-character-certificate-sha256"

  - "vless://uuid@example.com:443?security=tls&sni=example.com#VLESS"
```

`type` 和 `protocol` 等价。Young、Naive 以及 WutherCore 后续增加的协议不需要等待 Mihomo 增加对应节点类型。

需要强类型校验和完整嵌套配置时，可以直接使用本地 `nodes` 相同的结构：

```yaml
nodes:
  Young 主节点:
    type: young
    address: "[2001:db8::10]:443"
    login:
      user: "base64url-encoded-32-byte-key"
    secure:
      tls: true
      sni: young.example.com
    params:
      authority: young.example.com
      path: /assets
      pin-sha256: "64-character-certificate-sha256"
      padding-min: 64
      padding-max: 512
```

映射键会作为节点名，因此内部可以省略 `name`。节点也可以直接是 URI 字符串；URI scheme 本身就是协议类型。

省略 `type` 时，解析器只根据有明确含义的字段组合识别协议，例如：

- Young：`key/password` 与 `pin-sha256`
- WireGuard：`peers` 或成对的私钥、公钥字段
- VMess：`alterId`
- VLESS：`flow`、REALITY 字段或 UUID
- AnyTLS：`clientId` 或会话检查字段
- Shadowsocks：`cipher` 与 `password`
- SSH、SSR、TUIC、Hysteria、Hysteria 2 和 Snell 的专属字段

只有用户名、密码、服务器和端口时，HTTP、SOCKS5、Trojan 等协议无法无歧义地区分，必须填写 `type`。解析器不会用不可靠的默认协议代替用户选择。

Base64 解码后会重新执行同一套探测，所以 Base64 包装的原生 YAML、JSON、Mihomo YAML、SIP008 和 URI 列表均可使用。无效正文会使本次更新失败并回退缓存，不会把正在使用的节点替换为空列表。提供者确实需要发布空订阅时应明确返回 `nodes: []`。

可直接用于生成器和解析测试的完整正文见
[`examples/subscription-native.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/subscription-native.yaml)。

## Age 加密订阅

`age-secret-key` 只在响应正文以官方 ASCII Armor 头开始时解密；普通明文仍会正常解析。这与 Mihomo 的行为一致。

支持两类私钥：

- X25519：`AGE-SECRET-KEY-...`
- ML-KEM-768/X25519 混合后量子密钥：`AGE-SECRET-KEY-PQ-...`

一个字段可以包含多行密钥和以 `#` 开头的注释。配置检查会验证 Bech32、密钥类型和 32 字节私钥长度。Age 公钥不会被自动发给订阅服务器；服务商要求公钥时，应按其约定放入 `header`，常见名称是 `X-Age-Public-Key`。

缓存保存服务器返回的原始密文，每次从缓存恢复时都会重新解密。这样更换本地明文存储策略不会泄漏订阅正文。

## Mihomo 节点解析范围

解析器按照 Mihomo v1.19.29 的代理注册表识别全部 26 类节点：

- `ss`、`ssr`、`socks5`、`http`
- `vmess`、`vless`、`trojan`、`anytls`
- `snell`、`ssh`、`mieru`、`sudoku`、`trusttunnel`
- `hysteria`、`hysteria2`、`tuic`、`wireguard`
- `direct`、`dns`、`reject`、`rematch`
- `shadowquic`、`gost-relay`、`masque`、`openvpn`、`tailscale`

节点的所有顶层字段、数组和嵌套对象都会保留。Hysteria 的 `ports`、Mieru 的 `port-range`、WireGuard 多 Peer、SSH 主机密钥、WebSocket、gRPC、HTTP/2、REALITY、ECH 和自定义协议字段不会因为兼容模型只提供字符串参数而被丢弃。端口会严格检查为 `1..=65535`；不会再把超范围端口截断成另一个值。

## 解析支持与运行时支持

“能解析”表示订阅节点及全部字段可以被读入；“能运行”还要求 WutherCore 已有对应出站协议。

当前 Mihomo 节点中尚缺少 6 个运行时出站：

- `shadowquic`
- `gost-relay`
- `rematch`
- `masque`
- `openvpn`
- `tailscale`

这些节点会被完整解析并明确记录为未实现协议，但不会进入运行时注册，因此不会因为一条未知节点导致同一订阅中的可用节点全部更新失败。

Mihomo 的其余 20 类节点已有对应运行路径。其中 `reject` 映射到 Block，`dns` 映射到 DNS Hijack。WutherCore 另外提供 Mihomo 当前注册表之外的 Naive 和 Young 出站。
