---
title: 配置文件
description: 顶层字段、Profile 默认值、日志和配置校验
---

# 配置文件

WutherCore 读取 `version: 1` 的 YAML。加载器先解析字段，再应用 Profile 默认值，
最后编译成 `RuntimePlan`。建议每次修改后依次运行：

```bash
wuther-core check config.yaml
wuther-core explain config.yaml
wuther-core run --config config.yaml
```

`check` 只做加载和编译，不启动监听器。`explain` 输出 JSON 运行计划。`run` 在启动
外部资源前还会检查当前二进制是否包含配置要求的组件。

## 最小配置

```yaml
version: 1
profile: desktop
name: laptop

feeds:
  primary: https://example.com/subscription
```

这个文件会由 `desktop` Profile 补出本地 Mixed 监听、面板、`main` 分组、路由、
DNS、Smart、UI 和 Mesh 默认配置。使用 `explain` 查看最终结果，不要根据省略的
YAML 字段推断功能一定关闭。

## 顶层字段

| 字段 | 类型 | 省略行为 | 说明 |
| --- | --- | --- | --- |
| `version` | 非负整数 | 不可省略 | 当前必须为 `1` |
| `profile` | `desktop`、`router`、`server`、`mobile` | `desktop` | 选择整块配置缺失时的默认值 |
| `name` | 字符串 | 不设置 | 配置实例的显示名称 |
| `log` | 对象 | 使用 Profile 后的日志默认 | 日志级别、过滤器、输出和连接摘要 |
| `database` | 对象 | 启用 Turso 和默认路径 | 持久化流量、学习结果、DNS 缓存和面板状态 |
| `listen` | 对象 | 由 Profile 创建 | Mixed、面板和服务端协议监听 |
| `feeds` | 名称到订阅定义的映射 | 空 | 远程或内联节点来源 |
| `nodes` | 节点列表 | 空 | URI 短写或结构化手动节点 |
| `groups` | 名称到分组定义的映射 | 自动创建 `main` | 手动、Smart、测速和负载分散策略 |
| `rule-providers` | 名称到 Mihomo provider 的映射 | 空 | 兼容入口，编译时合并到 `route.sets` |
| `route` | 对象 | 由 Profile 创建 | 预设、步骤、规则集和最终出站 |
| `resolver` | 对象 | 由 Profile 创建 | DNS 服务、服务组、规则、缓存和 Fake IP |
| `capture` | 对象 | 由 Profile 创建 | TUN、TPROXY、REDIRECT 和平台过滤 |
| `smart` | 对象 | 使用默认配置 | 学习目标、窗口、粘性和解释 |
| `ui` | 对象 | 使用默认配置 | 原生 API、Clash 兼容 API、密钥和 CORS |
| `mesh` | 对象 | 创建 Tailscale 默认块 | Tailnet 直连和 userspace 协同 |
| `find-process-mode` | `off`、`strict`、`always` | `strict` | 控制连接的进程反查 |

所有标准键名、别名和源码位置见[根字段索引](generated/core.md)。

## Profile 默认值

Profile 只补整块缺失的配置。显式字段优先。

| 配置 | desktop | router | server | mobile |
| --- | --- | --- | --- | --- |
| `listen.local` | `7890` | `7890` | 不创建 | `7890` |
| `listen.panel` | `9090` | `9090` | `127.0.0.1:9090` | `9090` |
| `listen.share` | `false` | `home` | `false` | `false` |
| 缺失的 `groups` | 创建 `main` | 创建 `main` | 创建 `main` | 创建 `main` |
| `route.preset` | `cn_smart` | `cn_smart` | `global` | `cn_smart` |
| `route.final` | `main` | `main` | `main` | `main` |
| `resolver.mode` | `normal` | `normal` | `normal` | `normal` |
| `capture.on` | `false` | `true` | `false` | `false` |
| `smart` | 默认启用 | 默认启用 | 默认启用 | 默认启用 |
| `ui` | 默认启用 | 默认启用 | 默认启用 | 默认启用 |
| `database` | 默认启用 | 默认启用 | 默认启用 | 默认启用 |

当 DNS 服务为空时，默认加入：

```yaml
resolver:
  servers:
    ali: https://223.5.5.5/dns-query
    cloudflare: https://1.1.1.1/dns-query
  nameserver: [ali]
  fallback: [cloudflare]
```

默认 `main` 分组引用所有订阅。如果存在手动节点，还会引用保留入口 `nodes`。

## 默认值的三个层次

### Serde 字段默认

字段表中的 `serde(default)` 在解析时立即生效，例如空列表、`false` 或类型默认值。
这种默认与 Profile 无关。

### Profile 默认

Profile 在解析后运行，只为缺失的配置块补值。下面两个配置的语义不同：

```yaml
# 缺失 listen，Profile 可以创建 local 和 panel
version: 1
profile: desktop
```

```yaml
# listen 已存在，字段按 Listen 自身的默认规则处理
version: 1
profile: desktop
listen:
  share: false
```

### 编译期归一化

短写、兼容别名和引用会在编译为 `RuntimePlan` 时展开。例如：

- `listen.local: 7890` 变成明确的主机和端口。
- 节点 URI 变成 `NodeDetail`。
- 顶层 `rule-providers` 合并到 `route.sets`。
- 分组来源解析成实际节点集合。
- 路由字符串步骤变成 matcher 和 action。

## 日志

```yaml
log:
  on: true
  level: info
  filter: "info,core_runtime=debug"
  stdout: true
  format: text
  file:
    on: true
    path: data/logs/wuthercore.log
  connection-summary-interval: 1m
```

| 字段 | 说明 |
| --- | --- |
| `on` | 总开关。关闭后不初始化本配置的日志输出 |
| `level` | 基础等级，接受 `off`、`error`、`warn`、`info`、`debug`、`trace` |
| `filter` | `tracing_subscriber` 过滤表达式，可按 crate 或 target 覆盖等级 |
| `stdout` | 是否写标准输出 |
| `format` | `text` 供人工阅读，`json` 供采集器解析 |
| `file.on` | 是否启用文件输出 |
| `file.path` | 日志路径，父目录会按运行时实现创建 |
| `connection-summary-interval` | 连接表汇总周期，`0s` 或小于 `1s` 视为关闭 |

连接摘要使用 `conntable` target，包含总连接数、主要目的地、主要进程、规则、
出站和长连接。生产环境建议从 `30s` 到 `5m`。

## 数据库

```yaml
database:
  enabled: true
  path: data/state/wuthercore.db
  relative-to: cwd
  busy-timeout: 5s
  max-write-attempts: 12
  multiprocess-wal: auto
  experimental-vacuum: true
```

数据库使用 Turso 的异步本地引擎。累计流量、Smart 学习结果、分组手动选择、DNS
缓存和 Clash 面板存储共用 `path` 指定的主数据库。不会读取、删除或迁移旧格式
数据库。

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `enabled` | `true` | 是否启用持久化。关闭后只保留本次进程内状态 |
| `path` | `data/state/wuthercore.db` | Turso 主数据库文件，可使用任意文件名和绝对路径 |
| `relative-to` | `cwd` | 相对路径基准。`cwd` 使用进程工作目录，`config` 使用配置文件目录 |
| `busy-timeout` | `5s` | 遇到并发写锁时的等待时间 |
| `max-write-attempts` | `12` | 可重试写冲突的最大尝试次数 |
| `multiprocess-wal` | `auto` | `auto` 按平台能力启用，`on` 强制启用，`off` 禁用 |
| `experimental-vacuum` | `true` | 启用 Turso 的增量空间回收能力 |

`multiprocess-wal: auto` 适合大多数部署。它允许支持的平台由运行中的核心和独立 CLI
同时访问数据库。`on` 不会降级，平台不支持时启动直接失败。数据库启用时，路径无效
或数据库无法打开也会阻止核心启动，防止持久化静默失效。

使用配置文件中的数据库设置查询状态：

```bash
wuther-core store info --config config.yaml
wuther-core traffic --config config.yaml
```

`--path` 可以临时覆盖文件路径。与 `--config` 同时使用时，其余 Turso 参数仍取自配置。

## 进程反查

| 值 | 行为 | 成本 |
| --- | --- | --- |
| `off` | 从不查询进程 | 最低，Dashboard 进程列为空 |
| `strict` | 路由含进程条件时查询 | 默认，按需产生系统调用 |
| `always` | 每条 TCP 和 UDP 连接都查询 | 信息最完整，系统调用最多 |

Linux、Windows、macOS 和 Android 的实现与权限不同。规则需要进程字段而系统无法
查询时，按运行时错误和未匹配处理，不会伪造进程名。

## 字段命名和别名

文档优先展示标准键名。兼容别名只用于旧配置和第三方导入。例如
`find-process-mode` 的别名是 `find_process_mode`。新配置应使用标准键名，
这样迁移输出、示例和错误路径保持一致。

对象启用 `deny_unknown_fields` 时，拼错键名会立即失败。未启用严格未知字段拒绝的
兼容对象仍会在归一化或协议注册器阶段检查不支持的组合。

## 配置安全

- 不要提交订阅 URL、密码、私钥、API 密钥、Age 私钥或完整节点 URI。
- 面板监听非回环地址或 `listen.share` 为 `home`、`all` 时，必须设置
  `ui.secret`。
- `explain` 可能包含节点和认证信息。共享输出前先脱敏。
- 普通相对文件路径按进程工作目录解析。`database.relative-to` 可单独选择工作目录或
  配置文件目录。

## 验证结果怎么理解

`check` 成功证明：

- YAML 能被解析。
- Profile 和短写能被展开。
- 名称引用存在。
- 字段范围和已实现组合通过校验。
- 能构建运行计划。

`check` 不会证明：

- 远程订阅和规则集当前可下载。
- 节点凭据正确。
- 目标平台拥有 TUN、防火墙或绑定端口权限。
- 网络路径和证书在运行时可达。

这些问题需要 `feeds refresh`、`ruleset refresh`、实际 `run` 和平台日志继续验证。
