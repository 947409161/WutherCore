---
title: 协议与传输概览
description: WutherCore 入站、出站、传输和可选组件导航
---

# 协议与传输概览

WutherCore 将“协议”“传输”“TLS/伪装”和“系统隧道”分开组合。配置编译阶段会拒绝
未知字段、未编译组件和不支持的组合，不会静默注册占位实现。

## 入站

| 类型 | 能力 |
| --- | --- |
| Mixed | HTTP CONNECT、普通 HTTP 代理、SOCKS5 CONNECT、UDP ASSOCIATE |
| Shadowsocks | AEAD、2022、TCP/UDP、SIP003、SIP022 EIH、多用户 |
| VLESS / gRPC / REALITY | 认证、服务端传输和 TLS 组合 |
| XHTTP / SplitHTTP | HTTP/1.1、HTTP/2、HTTP/3 与多种流模式 |
| WireGuard / Young | 正式服务端入站 |
| 系统接管 | TUN、TPROXY、REDIRECT、Android VpnService |

## 出站

| 类别 | 协议 |
| --- | --- |
| 基础动作 | Direct、Block、DNS Hijack |
| 通用代理 | HTTP、SOCKS5 |
| Shadowsocks 系列 | Shadowsocks、2022、SSR、Snell |
| TLS 与 UUID | Trojan、VLESS、VMess、AnyTLS |
| QUIC 与现代隧道 | Hysteria、Hysteria 2、TUIC、Young |
| 专用协议 | Mieru、Sudoku、TrustTunnel |
| 系统/远程隧道 | WireGuard、SSH |
| 可选组件 | Naive + Cronet |

## 传输与伪装

通用传输层覆盖 TCP、TLS、REALITY、WebSocket、HTTP 混淆、HTTP/2、gRPC、
XHTTP、SplitHTTP、uTLS、ECH 和 FinalMask。具体组合取决于协议、服务端能力和
编译时组件。

<div class="grid cards" markdown>

-   **AnyTLS**

    认证、动态 padding、会话复用、SYNACK 与 UoT v2。

    [阅读指南](../ANYTLS.md)

-   **Hysteria**

    Hysteria 1/2、TCP/UDP、端口跳跃、混淆与 Brutal。

    [阅读指南](../HYSTERIA.md)

-   **WireGuard**

    用户态双栈网络栈、多 Peer 路由与正式入站。

    [阅读指南](../WIREGUARD.md)

-   **Young**

    基于 Neqo/NSS、HTTP/3 与 WebTransport 的原生协议。

    [阅读指南](../YOUNG_PROTOCOL.md)

-   **XHTTP**

    HTTP/1.1、HTTP/2、HTTP/3、XMUX、TLS/REALITY/uTLS/ECH。

    [阅读指南](../XHTTP.md)

-   **Naive**

    Cronet H2/H3、UoT v2、ECH；需要单独满足 GPL 许可。

    [阅读指南](../NAIVE.md)

</div>

## 编译期选择

所有协议和传输均可通过 Cargo features 精确裁剪：

```bash
cargo build --release -p wuther-core \
  --no-default-features \
  --features "with_quic,with_vless,with_grpc,with_utls"
```

完整预设、标签表和 CI 等价用法见[组件化构建](../BUILDING.md)。
