---
title: 命令行参考
description: wuther-core 全部子命令、参数、输出和推荐工作流
---

# 命令行参考

命令行由当前二进制直接定义。不同组件化构建拥有相同的基础命令，但运行配置时会检查
所需组件是否存在。

```text
wuther-core <COMMAND>
```

使用 `wuther-core --help` 查看当前版本帮助，使用
`wuther-core <COMMAND> --help` 查看子命令参数。

## 命令总览

| 命令 | 作用 | 是否访问网络 | 是否修改数据 |
| --- | --- | --- | --- |
| `run` | 前台启动内核 | 按配置 | 是 |
| `check` | 解析并校验配置 | 通常否 | 否 |
| `explain` | 输出归一化后的 RuntimePlan JSON | 通常否 | 否 |
| `migrate` | 将第三方配置迁移为 Friendly YAML | 否 | 写输出文件 |
| `feeds list` | 列出订阅 | 否 | 否 |
| `feeds refresh` | 立即刷新订阅 | 是 | 写缓存 |
| `store info` | 查看持久化状态摘要 | 否 | 否 |
| `store reset` | 重置持久化状态 | 否 | 是 |
| `ruleset list` | 列出规则集 | 否 | 否 |
| `ruleset refresh` | 拉取并解析规则集 | 是 | 写缓存 |
| `ruleset convert` | 转换规则集格式 | 否 | 写输出文件 |
| `components` | 查看编译组件 | 否 | 否 |

## `run`

```bash
wuther-core run --config config.yaml
wuther-core run -c config.yaml
```

`--config` 和 `-c` 指定配置文件。启动流程包括解析、Profile 补全、引用解析、运行计划
构建、组件检查和数据面激活。任一步失败都会返回非零状态。

该命令以前台方式运行。服务管理器应传递终止信号并等待清理完成，特别是启用 TUN、
路由或防火墙时。

## `check`

```bash
wuther-core check config.yaml
```

检查范围包括：

- YAML 解析和未知字段
- Profile 默认值补全
- 节点、分组、规则集和 DNS 名称引用
- 字段组合和范围
- 当前二进制组件能力
- RuntimePlan 能否构建

它不会证明远端节点可连接，也不会保证订阅、远程规则集或证书在未来仍有效。适合 CI、
部署前检查和配置编辑器保存钩子。

## `explain`

```bash
wuther-core explain config.yaml > runtime-plan.json
```

输出编译后的 RuntimePlan JSON，可检查：

- Profile 实际补上的监听、分组、路由和 DNS
- 短写和兼容字段的归一化结果
- 名称引用解析后的目标
- Smart、Capture、UI 和 Mesh 的最终开关

输出可能包含地址、节点信息或其它部署数据。上传诊断前先检查和脱敏。

## `migrate`

```bash
wuther-core migrate mihomo input.yaml --output config.yaml
wuther-core migrate mihomo input.yaml -o config.yaml
```

位置参数依次是源类型和输入文件，`--output` 或 `-o` 指定输出。当前源类型支持
`mihomo`。迁移只负责语法和语义映射，随后必须运行：

```bash
wuther-core check config.yaml
wuther-core explain config.yaml
```

无法无损映射的第三方字段应在迁移报告和最终配置中人工审查。

## `feeds`

### `feeds list`

```bash
wuther-core feeds list config.yaml
```

读取配置并列出订阅名称、来源和调度信息，不主动刷新。

### `feeds refresh`

```bash
wuther-core feeds refresh config.yaml
wuther-core feeds refresh config.yaml --cache-dir data/feeds
```

立即拉取并解析配置中的订阅。`--cache-dir` 覆盖缓存目录。命令会访问远程 URL，
失败时返回非零状态。认证头、URL token 和缓存内容按敏感信息处理。

## `store`

### `store info`

```bash
wuther-core store info
wuther-core store info --config config.yaml
wuther-core store info --path data/state/wuthercore.db
```

输出 Turso store 的路径、文件大小和各命名空间行数，包括累计流量、节点学习、
站点最佳节点、固定选择和分组手动状态。`--path` 优先于配置文件中的数据库路径。

### `store reset`

```bash
wuther-core store reset
wuther-core store reset --config config.yaml
wuther-core store reset --path data/state/wuthercore.db
```

重置指定 store。此操作会清除累计流量、学习结果和手动选择，保留 schema 与面板通用
存储。Turso 多进程 WAL 可用时不要求停止核心。

## `traffic`

```bash
wuther-core traffic --config config.yaml
wuther-core traffic --path data/state/wuthercore.db
wuther-core traffic --config config.yaml --category outbound --top 20
wuther-core traffic --config config.yaml --exact
wuther-core traffic --config config.yaml --json
```

优先直接读取持久化 Turso 数据库。传入 `--config` 时自动使用 `database` 路径和参数，
也会读取 API 地址与密钥作为平台不支持多进程 WAL 时的回退。分类包括网络、入站、
入站类型、入站用户、出站、策略组、Provider、规则、规则载荷、进程、源地址、目标
地址、端口、GeoIP、ASN 和 UID。

默认输出适合人工阅读的单位，最大显示单位为 BB。`--exact` 同时显示无损十进制字节数。
`--json` 中上传与下载总量始终是十进制字符串，不受整数位数限制。

## `ruleset`

### `ruleset list`

```bash
wuther-core ruleset list config.yaml
```

列出配置中的规则集、类型、来源和更新信息，不执行远程刷新。

### `ruleset refresh`

```bash
wuther-core ruleset refresh config.yaml
wuther-core ruleset refresh config.yaml --cache-dir data/rulesets
```

拉取并解析全部规则集，输出条目数和匹配器统计。远程源、缓存权限、校验和或签名策略
失败都会导致命令失败。

### `ruleset convert`

```bash
wuther-core ruleset convert geosite-cn.yaml geosite-cn.rrs
wuther-core ruleset convert ruleset.json ruleset.txt
wuther-core ruleset convert input.rrs output.yaml --output-format yaml
wuther-core ruleset convert input.bin output.rrs --input-format srs
```

位置参数是输入和输出。输入格式可自动嗅探，也可用 `--input-format` 指定。
输出格式按扩展名判断，也可用 `--output-format` 覆盖。

| 方向 | 支持格式 |
| --- | --- |
| 输入 | `yaml`、`txt`、`list`、`json`、`rrs`、`mrs`、`srs` |
| 输出 | `yaml`、`txt`、`json`、`rrs` |

转换前后应比较条目数，并在目标版本上测试实际匹配。

## `components`

```bash
wuther-core components
wuther-core components --json
```

文本输出适合人工查看，JSON 输出适合脚本和部署平台。当前可报告的组件标签包括：

```text
with_api
with_tun
with_anytls
with_grpc
with_hysteria
with_hysteria2
with_http
with_http_transport
with_mieru
with_naive
with_quic
with_reality
with_shadowsocks
with_shadowsocksr
with_snell
with_socks
with_ssh
with_sudoku
with_trojan
with_trusttunnel
with_tuic
with_utls
with_vless
with_vmess
with_wireguard
with_ws
with_xhttp
with_young
```

标签是否出现取决于构建时选择。完整编译方式和标签依赖关系见
[组件化构建](../BUILDING.md)。

## 推荐工作流

### 本地编辑

```bash
wuther-core check config.yaml
wuther-core explain config.yaml
wuther-core run -c config.yaml
```

### 部署流水线

```bash
wuther-core components --json
wuther-core check config.yaml
```

流水线应先比较构建组件与部署要求，再校验配置。不要等到服务重启时才发现二进制缺少
协议组件。

### 更新外部数据

```bash
wuther-core feeds refresh config.yaml --cache-dir data/feeds
wuther-core ruleset refresh config.yaml --cache-dir data/rulesets
wuther-core check config.yaml
```

缓存目录应使用持久化卷，并限制读取权限。

## 退出状态与日志

成功命令返回 `0`，参数错误、配置错误、组件缺失、网络失败、转换失败或激活失败返回
非零状态。自动化脚本必须检查退出状态，不能只搜索日志文本。

日志格式、级别和文件输出由配置的 `log` 块决定。详细字段见
[根配置字段索引](generated/core.md#log)。
