# Changelog

本文件记录用户可见的重要变化。正式版本的发布说明由 GitHub Release 根据 `.github/release.yml` 分类生成，并补充兼容性、已知限制和升级方式。

## [Unreleased]

### Changed

- Linux 与 Android Root TUN 强制校验 `CAP_NET_ADMIN`，启用完整批量收发、
  GSO/GRO、4096 包发送队列和批量回写。TUN 热路径不再逐批分配借用向量。
- TCP 拨号改为 Tokio reactor 原生非阻塞 connect，不再为每条连接创建
  `spawn_blocking` 任务。Android 运行时限制为 2 至 4 个 worker，减少大小核迁移。
- smoltcp fallback 改用每连接 `AtomicWaker` 与协议栈 deadline 驱动，移除
  `Pending` 时逐次创建任务和固定 20ms 空转。
- groups 系统新增 `proxies`, glob 成员来源, 嵌套 Manual 分流组, 候选上下限,
  默认选择, 显式空组回退, 常驻探活和成员权重。新增 Random 与 Weighted 策略。
- 组依赖使用 petgraph 做拓扑检查与循环路径定位，成员使用 IndexMap 保持声明顺序，
  globset 预编译选择器。订阅刷新通过 ArcSwap 原子发布，选择链使用 SmallVec。
- 路由, DNS, Clash API 与原生 API 统一递归解析策略组。API 现在返回直接选择,
  最终节点和完整选择链，组测速会展开到实际叶子节点。
- 官方多平台配置改为 23 个中文策略组，加入主要国家与地区节点过滤，并使用
  `luestr/IconResource` 远程图标。
- 官方 DNS 基线改为国内主解析与国外 fallback。已知国内外规则集分别进入对应
  DNS 组，未分类域名按 GeoIP 结果回退，节点域名使用独立直连引导解析。

### Fixed

- 修复节点或 provider 自定义 `SO_MARK` 覆盖 Root TUN 绕行标记后，节点连接被
  TUN 再次接管并作为普通目标写进连接表的问题。TCP 与 UDP 均以接管绕行标记为最终值。
- TCP relay 支持真正的双向半关闭。已经传输有效数据后的 `ECONNRESET`
  不再中断已完成的另一方向，也不再作为失败连接输出 `os error 104`。

## [0.3.6] - 2026-07-29

### Added

- 直接路由完整支持 Mihomo 官方规则面，逻辑规则，`SUB-RULE`，`PASS`，
  `PASS-RULE` 和按序 `no-resolve`；Classical provider 支持除 `RULE-SET`，
  `SUB-RULE` 外的全部官方规则类型。
- 域名匹配统一支持 IDNA，Unicode，Clash domain wildcard，Mihomo
  `DOMAIN-WILDCARD`，regexp2 风格正则与 MRS domain trie。
- RRS 升级至 v3，新增扩展 classical section，在保留 v1/v2 读取兼容的同时
  无损保存新增规则类型和修饰符。
- 新增多线程分片流量计数器、连接级流量批量归并、无锁脏会话与脏行队列。
- 新增高并发流量累计、二十万级分类更新和两万活跃连接回归测试。

### Changed

- 流量持久化按变化增量提交，不再每两秒扫描全部历史分类；普通数据块不再逐项
  更新全部持久分类。
- 连接最大速率改为面板快照时采样，数据转发路径不再读取系统时钟、获取速率锁
  或扫描十个时间桶。
- TCP relay 缓冲区从每方向固定 32 KiB 改为 8 KiB 至 64 KiB 自适应，降低海量
  空闲连接内存占用，同时保留大流量吞吐。
- Clash `/connections` 的所有 WebSocket 客户端共享一个快照生产器，自定义
  interval 只限制单客户端发送节奏；连接快照取消无意义的全表排序并直接序列化。
- 连接、路由、协议握手和逐包诊断日志降为 debug 或 trace，默认 info 不再为每条
  成功连接同步格式化和输出多条日志。

### Fixed

- 修复高吞吐时每个数据块争用速率锁、持久分类原子和全局流量缓存行导致的 CPU
  占用、耗电与发热异常。
- 修复历史流量分类增长后，即使没有新流量也会周期性全表扫描并持续消耗 CPU 的问题。
- 修复多个带 interval 参数的 dashboard 各自重复构建完整连接快照的问题。

## [0.3.5] - 2026-07-29

### Added

- Manual、Smart、Fast、Stable 和 Spread 统一支持持久策略组 pin。Clash 与原生
  API 暴露节点、世代、创建时间、来源和可用状态。
- 策略组新增 `expected-status`、`interval`、`idle-timeout`、`tolerance`、
  `unified-delay`、Spread `strategy`、节点与协议过滤、拨号失败阈值和 UDP 开关。
- URLTest 历史新增连接、TLS 握手、响应和统一延迟分项，支持 IPv6 URL 和完整
  HTTP 响应头。

### Changed

- 自动策略的 pin 节点失活时临时故障转移但保留用户意图。成功执行 Clash 组测速
  后按 pin 世代解锁并立即恢复自动选择；失败测速和过期并发测速不会清除 pin。
- URLTest 改为活跃组按需调度、闲置停止、惰性有界并发、同节点同 URL 合并、
  最短共享间隔、失败指数退避和 provider 节点回收。启动不再扫描全部订阅节点。
- Smart 选择改为线性热路径，综合 P50、P90、抖动、成功率、退化基线、被动吞吐、
  活跃连接和站点或会话记忆。数据面流量统计使用原子累计和粗粒度时钟门。
- Fast 在延迟差不超过 tolerance 时应用 `prefer`，Stable 使用优先层级，
  自动策略只在正常候选不可用时使用 `avoid`。
- 策略组 pin 的内存变更与 Turso 提交串行化。数据库失败会回滚运行时状态并由
  API 返回错误。

### Fixed

- `disable-udp` 现在由真实选点入口执行，不再只影响 Clash API 展示。
- 组级测速、历史和 `testUrl` 使用该组配置的 URL 与统一延迟覆盖。
- Smart `sticky: session` 现在使用独立会话键，`site` 使用公共后缀列表计算可注册
  域名。

## [0.3.3] - 2026-07-28

### Added

- 新增持久化累计流量汇总。统计支持任意精度总字节数，并覆盖全部运行时分类。
- 新增 `traffic` 命令。默认输出便于阅读的单位，最大单位为 BB；`--exact` 与 `--json` 保留完整十进制数值。
- 策略组支持 `hidden` 与 `icon`。图标接受 URL 和 Base64 data URI，并通过 Clash API 暴露。
- 顶层 `database` 配置支持自定义 Turso 文件路径和完整运行参数。

### Changed

- 持久化引擎从 redb 切换到 Turso 0.7.1。数据库访问改为全异步多连接架构，并使用短事务和缓存预编译语句。
- 旧数据库文件不会被读取或变更。新数据库路径完全由 `database.path` 控制。
- `store info` 与 `store reset` 以及 `traffic` 支持通过 `--config` 复用运行时数据库设置。

### Fixed

- provider 中的 `skip-cert-verify`，`allowInsecure` 等旧式扁平 TLS 字段不再被错误写入严格的 Xray `tlsSettings`。它们现在通过独立的传输兼容开关生效，包含 XHTTP 节点的订阅可以正常原子激活；结构化 `tlsSettings.allowInsecure=true` 仍保持拒绝。

## [0.3.2] - 2026-07-28

### Fixed

- provider 节点在激活后进入统一运行时快照，Clash `/proxies`，`/providers/proxies`，策略组成员和原生 `/nodes` 现在使用同一份有效节点数据。
- provider 刷新会递增节点版本并立即重建 API 缓存，不再等待缓存 TTL，也不会继续显示已被订阅移除的旧节点。
- provider 节点补全 Direct，Reject，Dns，Naive，Sudoku，TrustTunnel 和 Young 的 Clash 类型映射。
- provider 激活失败时保留上一份运行时快照和状态，名称重复，静态节点冲突，策略组冲突及保留名称冲突会整批拒绝。

### Changed

- GitHub CI，Build Matrix 和 Release 的 macOS 自动构建仅保留 Apple Silicon，不再运行或发布 Intel macOS 产物。
- Release 直接复用标签提交已经通过的 `Required CI`，不再重复运行完整 CI；产物只下载一次并直接校验、签名和发布，中间构建 artifact 仅保留 1 天。

## [0.3.1] - 2026-07-28

### Security

- Clash 兼容 `GET /configs` 的 `authentication` 只返回用户名，不再回传明文密码。

### Fixed

- Clash `PUT /configs` 的 `mode`（rule/global/direct）接入真实选路；
- `allow-lan` / `tun.enable` 热切换改为 `501`，不再写成功假象。
- 非本机管理面板（`listen.share: home|all` 或非 loopback `listen.panel`）在 `ui.secret` 为空时拒绝编译/启动。
- `groups.*.choose: chain` 在配置编译期拒绝，避免静默退化为单跳第一节点。
- `auto_route` / TPROXY / REDIRECT 下 capture 启动失败改为 fail-closed。

### Added

- 组网后端能力/附件模型、冻结 descriptor、强类型宿主资源声明与语义化系统资源冲突预检；
- 带阶段超时、调用方取消安全、逆序回滚、后台状态监控和 fail-closed 隔离的事务监督器；
- 基于 Unix process group/Windows Job 的托管 daemon、显式 readiness、后台退出监控、有界自动重启、脱敏日志与显式 `close` 契约；
- Linux、Android、Windows、macOS capture 与 DNS/Mixed/API 固定监听的实际资源声明，以及纯快照读取、URL/诊断/共享密钥安全投影的 `/v1/mesh/status`；
- 本阶段只交付通用组网基础设施，不包含 Tailscale、Cloudflare 等具体产品适配器，也不修改代理协议；
- 仓库文档中心、功能矩阵、架构、配置、API、排错和路线图；
- 结构化 Issue 表单、Pull Request 模板和 CODEOWNERS；
- Dependabot、依赖变更审查、CodeQL 与私密漏洞报告；
- 项目治理、紧急合并、安全、支持和行为准则；
- README 与 GitHub Social Preview 共用的品牌横幅。

### Changed

- README 改为按使用、集成和贡献场景组织；
- 合并门禁使用 `Required CI`，发布构建不作为 PR 必需检查；
- GitHub About、Topics、合并策略、标签和社区功能完成配置。

### Security

- 高危依赖变更会阻止 Pull Request 合并；
- CodeQL 初次扫描告警由 [Issue #9](https://github.com/MiChongs/WutherCore/issues/9) 跟踪，未批量忽略。

[Unreleased]: https://github.com/MiChongs/WutherCore/compare/v0.3.6...HEAD
[0.3.6]: https://github.com/MiChongs/WutherCore/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/MiChongs/WutherCore/compare/v0.3.4...v0.3.5
[0.3.3]: https://github.com/MiChongs/WutherCore/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/MiChongs/WutherCore/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/MiChongs/WutherCore/compare/v0.3.1-rc.5...v0.3.1
