---
title: 示例配置
description: WutherCore Desktop、Router、Android、订阅和 DNS 示例
---

# 示例配置

仓库中的 `examples/` 是可版本控制的起点。复制最接近部署场景的文件，再替换其中的
占位符；不要在原文件中写入真实订阅、密码或私钥。

## 场景选择

| 场景 | 文件 | 重点 |
| --- | --- | --- |
| 桌面普通代理 | [`desktop.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/desktop.yaml) | Mixed 监听、手动节点和基本路由 |
| 路由器/网关 | [`router.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/router.yaml) | TUN、自动路由和严格路由 |
| Android VpnService | [`android.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/android.yaml) | 非 root TUN、应用过滤和移动网络 |
| Android root TUN | [`android-root-tun.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-tun.yaml) | root `/dev/net/tun`、策略路由和包名过滤 |
| Android root TPROXY | [`android-root-tproxy.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-tproxy.yaml) | TCP、UDP、iptables 和策略路由 |
| Android root REDIRECT | [`android-root-redirect.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-redirect.yaml) | TCP、nftables 和 UID 过滤 |
| 高级 DNS | [`dns-advanced.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/dns-advanced.yaml) | 命名上游、策略和独立出口 |
| 自由订阅 | [`subscription-native.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/subscription-native.yaml) | 原生节点文档与协议探测 |
| Feed | [`with_feed.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/with_feed.yaml) | 订阅过滤、重命名和策略组 |
| 纯手动节点 | [`manual_only.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/manual_only.yaml) | 不依赖订阅服务 |
| 日常策略 | [`daily.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/daily.yaml) | 自定义策略组和规则 |

## Desktop

```yaml title="examples/desktop.yaml"
--8<-- "examples/desktop.yaml"
```

## Router

```yaml title="examples/router.yaml"
--8<-- "examples/router.yaml"
```

## Android VpnService

```yaml title="examples/android.yaml"
--8<-- "examples/android.yaml"
```

## Android root TUN

```yaml title="examples/advanced/android-root-tun.yaml"
--8<-- "examples/advanced/android-root-tun.yaml"
```

## Android root TPROXY

```yaml title="examples/advanced/android-root-tproxy.yaml"
--8<-- "examples/advanced/android-root-tproxy.yaml"
```

## Android root REDIRECT

```yaml title="examples/advanced/android-root-redirect.yaml"
--8<-- "examples/advanced/android-root-redirect.yaml"
```

四种 Android 数据面的权限要求和运行边界见
[Android 完整部署](manual/android.md)。

## 使用流程

1. 复制示例到仓库外或改名为 `config.yaml`。
2. 替换订阅地址、节点凭据、密钥与域名。
3. 运行 `wuther-core check config.yaml`。
4. 使用 `wuther-core explain config.yaml` 审计最终计划。
5. 先验证普通代理，再启用 TUN/TPROXY/REDIRECT。

字段语义、默认值和迁移规则见[配置指南](CONFIGURATION.md)。
