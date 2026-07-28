---
title: 运行管理
description: Smart、管理 API、Dashboard 与 Tailscale Mesh 的配置语义
---

# 运行管理

运行管理层包括 Smart 自动选路、UI 和 API、持久化状态以及 Tailscale Mesh。
这些能力不会改变配置文件的语法，但会影响运行期间的选择、管理面暴露和状态保存。

完整字段见[运行管理字段索引](generated/capture-runtime.md#smart)。

## Smart 自动选路

```yaml
smart:
  on: true
  goal: balanced
  learn: 14d
  sticky: site
  explain: true
```

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `on` | `true` | 启用学习和动态选择 |
| `goal` | `balanced` | 决定评分目标 |
| `learn` | `14d` | 学习结果的有效周期 |
| `sticky` | `site` | 决定选择结果的粘滞范围 |
| `explain` | `true` | 保留选择原因供诊断和 API 展示 |

### 目标

| `goal` | 优先方向 |
| --- | --- |
| `balanced` | 在速度、稳定性、成本与隐私之间平衡 |
| `speed` | 更重视延迟和吞吐表现 |
| `stability` | 更重视失败率和波动 |
| `low_cost` | 更重视节点成本约束 |
| `privacy` | 更重视隐私相关的策略信号 |

目标只改变评分偏好，不会绕过路由规则、分组成员限制或节点健康状态。

### 粘滞范围

| `sticky` | 行为 |
| --- | --- |
| `off` | 每次选择都可重新决策 |
| `site` | 同一站点尽量保持同一节点 |
| `session` | 同一会话保持选择 |

`site` 是默认值，适合登录态和 CDN 一致性。需要快速故障切换时，健康检查和不可用
状态仍可触发重选。

## 持久化状态

Smart 学习、站点最佳节点、固定选择和分组手动选择会写入 store。命令行提供：

```bash
wuther-core store info --config config.yaml
wuther-core store reset --config config.yaml
wuther-core traffic --config config.yaml
```

路径和 Turso 并发参数由顶层 `database` 配置控制，也可以用 `--path` 临时覆盖。
`reset` 会删除累计流量、学习和手动状态。具体参数见[命令行参考](cli.md#store)。

## UI 与 API

```yaml
listen:
  panel: 127.0.0.1:9090

ui:
  on: true
  secret: "replace-with-a-long-random-token"
  dashboard: auto
  api:
    native: true
    clash_compat: true
  cors:
    - https://admin.example.com
```

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `on` | `true` | 启用管理层 |
| `secret` | 不设置 | API Bearer token |
| `dashboard` | `auto` | Dashboard 资源选择或静态目录 |
| `api.native` | `true` | 开启 WutherCore 原生 API |
| `api.clash_compat` | `true` | 开启 Clash 兼容 API |
| `cors` | 空列表 | 允许的浏览器 Origin |

API 要求组件 `with_api`。`listen.panel` 决定实际绑定地址，`ui.on` 决定管理功能是否
启用。两者不是同一个开关。

### 安全边界

只要面板不是严格绑定回环地址，就必须：

1. 设置高熵 `ui.secret`。
2. 用防火墙限制来源。
3. 精确填写 `cors`，不要将任意来源当作生产默认值。
4. 通过 TLS 反向代理提供远程访问。
5. 避免将 Dashboard 和 API 直接公开到互联网。

`cors` 只约束浏览器，不是网络访问控制。命令行客户端和恶意服务不受浏览器同源策略
保护。

### Dashboard

`dashboard` 指向静态文件目录。目录不存在、入口文件缺失或进程没有读取权限时，
Dashboard 无法提供，但 API 的具体可用性仍由运行时检查决定。部署包可以不携带
Dashboard，此时保留 API 并由独立前端连接。

## Mesh

```yaml
mesh:
  tailscale:
    on: true
    mode: auto
    keep_tailnet_direct: true
    expose_as_node: false
```

`mesh.tailscale` 要求编译组件 `with_tailscale`。

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `on` | `true` | 启用该 Mesh 后端 |
| `mode` | `auto` | 选择连接本机 Tailscale 的方式 |
| `keep_tailnet_direct` | `true` | Tailnet 地址保持直连 |
| `expose_as_node` | `false` | 将 Mesh 能力暴露为可选节点 |
| `userspace_proxy` | 不设置 | 用户态模式的 SOCKS 或 HTTP 代理地址 |

### Tailscale 模式

| `mode` | 语义 |
| --- | --- |
| `auto` | 按运行环境选择可用后端 |
| `localapi` | 连接本机 Tailscale LocalAPI |
| `userspace` | 通过用户态 SOCKS 或 HTTP 代理 |
| `tsnet` | 使用内嵌 tsnet 路径 |
| `off` | 明确关闭 |

用户态代理示例：

```yaml
mesh:
  tailscale:
    mode: userspace
    userspace_proxy:
      socks: 127.0.0.1:1055
      http: 127.0.0.1:1056
```

`keep_tailnet_direct` 用于避免 Tailnet 流量被普通代理路径再次接管。关闭前应确认路由
不会形成回环。`expose_as_node` 会改变分组可见成员，启用后应重新检查分组和最终
路由。

## 启动检查

运行管理能力依赖编译组件和监听配置。建议按顺序确认：

```bash
wuther-core components
wuther-core check config.yaml
wuther-core explain config.yaml
```

`components --json` 适合部署脚本检查能力。`check` 验证引用和组合，`explain` 用于
确认 Profile 补全后的管理监听、Smart 策略和 Mesh 计划。
