---
title: 安装与运行
description: 下载、校验、配置并启动 WutherCore
---

# 安装与运行

最稳妥的路径是下载 GitHub Release、校验来源、复制示例配置，然后依次执行
`check`、`explain` 和 `run`。

## 1. 获取 WutherCore

=== "预编译发行版"

    [下载最新稳定版](https://github.com/MiChongs/WutherCore/releases/latest){ .md-button .md-button--primary }

    Release 覆盖 Linux GNU/musl、Android、Windows MSVC 和 macOS 的 AMD64/ARM64
    目标，并附带 `SHA256SUMS` 与 GitHub Artifact Attestation。

    ```bash
    sha256sum -c SHA256SUMS
    gh attestation verify <archive.zip> --repo MiChongs/WutherCore
    ```

=== "从源码构建"

    需要 Git、Rust 1.88+ 和目标平台工具链。

    ```bash
    git clone https://github.com/MiChongs/WutherCore.git
    cd WutherCore
    cargo build --release -p wuther-core
    ```

    需要裁剪组件或跨平台编译时，请使用[组件化构建](BUILDING.md)中的预设和
    `with_*` 标签。

## 2. 创建配置

=== "Linux / macOS"

    ```bash
    cp examples/desktop.yaml config.yaml
    ```

=== "Windows PowerShell"

    ```powershell
    Copy-Item examples\desktop.yaml config.yaml
    ```

最小配置：

```yaml
version: 1
profile: desktop
name: my-profile

listen:
  local: 7890
  panel: 127.0.0.1:9090
  share: false

feeds:
  airport: "https://example.com/subscription"

groups:
  main:
    choose: smart
    use: [airport]

route:
  preset: cn_smart
  final: main

resolver:
  mode: smart
```

!!! warning "替换占位符"

    示例域名、订阅地址、密码、UUID 和密钥不能直接用于生产环境。不要把真实凭据
    提交到仓库、Issue、Discussion 或日志。

## 3. 校验并启动

=== "Linux / macOS"

    ```bash
    ./wuther-core check config.yaml
    ./wuther-core explain config.yaml
    ./wuther-core run -c config.yaml
    ```

=== "Windows PowerShell"

    ```powershell
    .\wuther-core.exe check config.yaml
    .\wuther-core.exe explain config.yaml
    .\wuther-core.exe run -c config.yaml
    ```

`check` 会在创建监听器、路由或系统资源之前检查字段、凭据、协议组合、组件标签
和平台约束。`explain` 输出 Profile 补全后的 `RuntimePlan`，适合在正式启动前审计。

## 4. 验证普通代理

先保持 `capture.on: false`，确认本地 HTTP/SOCKS5 与 DNS 正常，再启用透明接管：

```bash
curl --proxy http://127.0.0.1:7890 https://example.com/
```

透明代理通常需要管理员、root 或宿主 VPN 权限。启用前阅读
[配置指南](CONFIGURATION.md)和[排错手册](TROUBLESHOOTING.md)。

## 下一步

<div class="grid cards" markdown>

-   **修改配置**

    Profile、订阅、策略组、路由与 DNS 的完整字段。

    [配置指南](CONFIGURATION.md)

-   **选择示例**

    Desktop、Router、Android、Feed 和高级 DNS 模板。

    [示例配置](examples.md)

-   **查看运行状态**

    原生 API、Clash 兼容接口、鉴权与 WebSocket。

    [管理 API](API.md)

-   **定位问题**

    TUN、DNS、订阅、权限和连接失败的诊断路径。

    [排错手册](TROUBLESHOOTING.md)

</div>
