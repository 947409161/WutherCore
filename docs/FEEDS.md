# Mihomo 订阅与代理提供者

WutherCore 的 `feeds` 可以直接读取 HTTP、HTTPS、`file://`、本地文件和内联节点。订阅正文支持 Mihomo YAML、Base64 包装的 Mihomo YAML、Base64 URI 列表、纯文本 URI 列表和 SIP008 JSON。

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

内联提供者可以直接写 Mihomo 节点：

```yaml
feeds:
  local:
    payload:
      - name: DIRECT
        type: direct
      - name: BLOCK
        type: reject
```

Mihomo `type: file` 可以写成本地路径或 `file://` URL。`migrate` 会把 Mihomo 的 HTTP、文件和内联 proxy-provider 转换为对应的 `feeds`。

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

Base64 解码后会重新执行完整格式探测，因此 Base64 包装的 Mihomo YAML 和 SIP008 也能正常工作。

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
