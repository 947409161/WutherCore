---
title: WutherCore 手册
description: 从配置加载到运行时行为的完整使用手册
---

# WutherCore 手册

这套手册以当前 `main` 分支代码为准，覆盖配置文件、命令行、编译组件、
协议、系统接管、管理接口和排错流程。它分成两层：

1. 语义手册解释字段为什么存在、怎样组合、何时生效，以及错误配置会怎样失败。
2. 完整字段索引从 Rust Serde 模型生成，列出实际接受的字段名、类型、默认规则、
   兼容别名、枚举写法和源码位置。

当前字段索引覆盖 **744 个可反序列化字段**和 **53 个枚举类型**。节点 `params`
由协议注册器动态解析，不属于 Serde 字段计数，它们的完整写法、默认值和约束集中在
[高级节点与协议参数](advanced-nodes.md)。CI 会重新扫描
`crates/core-config/src/model.rs` 与 `stream_settings.rs`。代码增加、删除或重命名
强类型字段后，如果参考页没有同步，文档检查会失败。

## 按任务阅读

| 任务 | 先读 | 再查 |
| --- | --- | --- |
| 写第一份配置 | [配置文件](configuration-file.md) | [根字段索引](generated/core.md) |
| 开本地端口或服务端入站 | [监听与入站](inbounds.md) | [入站字段索引](generated/inbounds.md) |
| 导入订阅或手动节点 | [订阅与节点](feeds-nodes.md) | [节点字段索引](generated/feeds-nodes.md) |
| 配置分组、路由和 DNS | [路由与 DNS](routing-dns.md) | [路由与 DNS 字段索引](generated/routing-dns.md) |
| 启用 TUN 或透明接管 | [系统接管](capture.md) | [接管字段索引](generated/capture-runtime.md) |
| 部署 Android root 或 VpnService | [Android 完整部署](android.md) | [接管字段索引](generated/capture-runtime.md) |
| 配置 Smart、API 或 Mesh | [运行管理](runtime-management.md) | [运行字段索引](generated/capture-runtime.md) |
| 配置 XHTTP 或 socket 行为 | [XHTTP 与 StreamSettings](xhttp-stream.md) | [XHTTP 字段索引](generated/xhttp.md) |
| 写全协议结构化节点 | [高级节点与协议参数](advanced-nodes.md) | [节点字段索引](generated/feeds-nodes.md) |
| 写复合路由、DNS DSL 和响应策略 | [高级路由、策略组与 DNS](advanced-routing-dns.md) | [路由与 DNS 字段索引](generated/routing-dns.md) |
| 组合独立下载、XMUX 和 FinalMask | [高级 XHTTP 与 FinalMask](advanced-xhttp-finalmask.md) | [StreamSettings 字段索引](generated/stream.md) |
| 部署到各操作系统或服务端 | [完整部署方案](deployment-recipes.md) | [组件化构建](../BUILDING.md) |
| 查命令和退出行为 | [命令行参考](cli.md) | [构建组件](../BUILDING.md) |

## 完整分类

### 配置入口

- [配置文件](configuration-file.md)
- [命令行参考](cli.md)
- [示例配置](../examples.md)
- [配置迁移](../CONFIGURATION.md)

### 网络能力

- [监听与入站](inbounds.md)
- [订阅与节点](feeds-nodes.md)
- [路由与 DNS](routing-dns.md)
- [系统接管](capture.md)
- [Android root 与 VpnService](android.md)
- [运行管理](runtime-management.md)
- [XHTTP 与 StreamSettings](xhttp-stream.md)

### 高级配置

- [全协议节点、动态参数和叠加规则](advanced-nodes.md)
- [复合路由、规则集、DNS 多出口和响应链](advanced-routing-dns.md)
- [XHTTP 模式、独立下载、socket 和 FinalMask](advanced-xhttp-finalmask.md)
- [Windows、macOS、Linux、路由器、Android 和服务端方案](deployment-recipes.md)

### 源码生成的逐字段索引

- [配置根、Profile 与日志](generated/core.md)
- [监听与服务端入站](generated/inbounds.md)
- [订阅、节点与出站](generated/feeds-nodes.md)
- [策略组、路由、规则集与 DNS](generated/routing-dns.md)
- [系统接管、Smart、UI 与 Mesh](generated/capture-runtime.md)
- [XHTTP 与 SplitHTTP 高级字段](generated/xhttp.md)
- [StreamSettings 与 socket 策略](generated/stream.md)

## 配置处理顺序

```mermaid
flowchart LR
    File["YAML 文件"] --> Serde["字段解析"]
    Serde --> Profile["Profile 默认值"]
    Profile --> Normalize["短写和兼容字段归一化"]
    Normalize --> Validate["引用和组合校验"]
    Validate --> Plan["RuntimePlan"]
    Plan --> Gate["编译组件检查"]
    Gate --> Runtime["运行时"]
```

理解这个顺序很重要：

- 字段拼错会在 Serde 阶段失败。大多数配置对象启用了未知字段拒绝。
- 省略字段不等于关闭功能。Profile 可能在下一步补上默认配置。
- `check` 成功表示配置能够编译成运行计划，不表示远程节点、订阅或规则集一定可用。
- `components` 显示二进制实际包含的 feature。配置需要的组件没有编译进去时，
  `run` 会明确拒绝启动。
- `explain` 输出补全和归一化后的计划，适合审查默认值和引用解析结果。

## 字段页的阅读方法

每个逐字段表使用同一套列：

| 列 | 含义 |
| --- | --- |
| YAML / JSON 字段 | 建议写入配置的标准键名 |
| 类型 | 解析后的 Rust 类型和容器形态 |
| 必填与默认 | Serde 是否允许省略，以及省略时调用的默认规则 |
| 兼容别名 | 为迁移或第三方格式保留的其它键名 |
| 取值 / 形态 | 枚举写法，或短写和长写的不同形态 |
| 解析与用途 | 字段说明、组合约束入口和权威源码位置 |

标准键名应优先于兼容别名。别名用于迁移，不保证长期作为文档主写法。

## 值的通用规则

### 时长

使用 `humantime` 写法，例如 `250ms`、`5s`、`10m`、`6h`、`14d`。某些
第三方兼容字段同时接受整数秒，字段索引会标出 `CompatDuration`。

### 地址

监听字段通常接受端口短写、`host:port` 字符串或对象长写。IPv6 地址与端口组合时
使用方括号，例如 `[::1]:9090`。是否允许域名、通配地址或端口 `0` 由对应配置块
校验。

### 名称和引用

订阅名、节点名、分组名、规则集名和 DNS 服务名都参与引用解析。名称区分大小写，
不能依赖显示层自动改写。删除被引用对象时，`check` 会报告引用位置。

### 空值和省略

- `Option<T>` 省略后通常表示不设置。
- 空列表表示明确没有成员，不会自动变成单元素列表。
- Profile 只在整个配置块缺失时补默认值。已经存在的配置块按字段自身默认规则解析。
- `false`、`0`、空字符串和省略是不同输入，校验阶段可能对它们采取不同处理。

## 权威性

发生冲突时按下面顺序判断：

1. 当前版本的配置反序列化和运行计划代码。
2. `wuther-core check` 与 `wuther-core explain` 的实际输出。
3. 本手册的源码生成字段索引。
4. 示例配置和迁移说明。

发现文档与代码不一致时，请提交 issue，并附上版本、最小配置和 `check` 输出。
