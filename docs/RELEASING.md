# 发版指南

WutherCore 使用 Git 标签驱动 GitHub Actions 发版。工作流只接受已经推送到仓库的标签，不会代替维护者创建或移动标签。

## 版本通道

| 通道 | 标签与 workspace 版本 | GitHub Release 行为 |
| --- | --- | --- |
| Pre-release | `vX.Y.Z-alpha.N`、`vX.Y.Z-beta.N`、`vX.Y.Z-rc.N` | 标记为 Pre-release，不会成为 Latest |
| Release | `vX.Y.Z` | 发布为正式版本，并标记为 Latest |

标签去掉前导 `v` 后，必须与 `Cargo.toml` 的 `[workspace.package].version` 完全一致。比如 `v0.4.0-rc.1` 对应 `version = "0.4.0-rc.1"`，不能只写 `0.4.0`。

正式版本的标签提交还必须已经进入 `main`。预发布可以来自候选分支，但仍会执行完整 CI。

## 发版前准备

1. 更新 `Cargo.toml` 中的 workspace 版本，并同步 `Cargo.lock`。
2. 把用户可见变化从 `CHANGELOG.md` 的 `Unreleased` 整理到对应版本。
3. 运行本地基线：

   ```bash
   cargo fmt --all --check
   cargo check --workspace --all-targets --locked
   cargo test --workspace --locked
   cargo doc --workspace --no-deps
   python scripts/check-repository.py
   ```

4. 通过 Pull Request 合入版本准备提交。正式版必须从 `main` 上的该提交打标签。

## 创建预发布

```bash
git switch main
git pull --ff-only
git tag -a v0.4.0-rc.1 -m "WutherCore 0.4.0-rc.1"
git push origin v0.4.0-rc.1
```

`alpha`、`beta` 和 `rc` 后必须带非负序号。工作流会从标签后缀自动判断这是 Pre-release。

## 创建正式发布

```bash
git switch main
git pull --ff-only
git tag -a v0.4.0 -m "WutherCore 0.4.0"
git push origin v0.4.0
```

正式标签没有预发布后缀。工作流会将其设为 Latest Release。

## 工作流保证

发布前会依次执行：

1. 校验标签格式、版本通道与 workspace 版本；
2. 确认正式版提交属于 `main`；
3. 在标签对应源码上运行格式、仓库完整性与 Linux workspace 校验；
4. 调用统一的 Build Matrix，并行构建全部 10 个目标；Windows 和 macOS
   产物会在对应架构的原生 runner 上执行冒烟验证；
5. 将每个平台 ZIP 作为非嵌套 artifact 上传，再按 `wuther-core-$VERSION-*` 前缀收集全部 10 个产物；
6. 生成 `SHA256SUMS`，再汇总为零压缩的 `release-assets` artifact；
7. 下载并解包汇总产物，生成 GitHub Artifact Attestation；
8. 使用 `.github/release.yml` 自动分类 Release Notes；
9. 直接上传文件到 GitHub Release，并按照标签设置 Pre-release 或 Latest。

正式发布不会覆盖已经发布的同名 Release。若首次发布在上传阶段中断，重新运行可以续传仍处于 Draft 状态的 Release；已发布的资产保持不可变。

## 发布产物

| 系统 | 架构 / ABI |
| --- | --- |
| Linux GNU | AMD64、ARM64 |
| Linux musl | AMD64、ARM64 |
| Android | ARM64、ARMv7 |
| Windows MSVC | AMD64、ARM64 |
| macOS | Intel、Apple Silicon |

每个 ZIP 包含：

- `wuther-core` 或 `wuther-core.exe`；
- `README.md` 与 MIT `LICENSE`；
- `examples/` 示例配置；
- `BUILD-COMPONENTS.txt` 版本、Rust target 与实际组件预设；
- `licenses/xray-transport-MPL-2.0.txt` 第三方许可证。

Linux GNU 与 macOS 默认归档使用 `standard`；Linux musl、Android 与 Windows
使用 `portable`。后者避开上游尚未覆盖这些目标的
Mozilla NSS/BoringSSL 构建链；可用目标仍能显式选择 `portable_boringssl` 或具体的
`with_grpc`、`with_utls`、`with_xhttp`。预设都会在 `BUILD-COMPONENTS.txt`
中明确记录，显式传入 `tags` 时则完全采用请求的组件集。

## 校验下载

Linux 或 macOS：

```bash
sha256sum -c SHA256SUMS
gh attestation verify wuther-core-0.4.0-linux-amd64.zip --repo MiChongs/WutherCore
```

PowerShell：

```powershell
Get-FileHash .\wuther-core-0.4.0-windows-amd64-msvc.zip -Algorithm SHA256
gh attestation verify .\wuther-core-0.4.0-windows-amd64-msvc.zip --repo MiChongs/WutherCore
```

## 手动重跑

在 GitHub Actions 的 `Release` 工作流中选择 `Run workflow`，填写一个已经存在的标签。通常保持 `channel = auto`；显式选择 `prerelease` 或 `release` 时，选择必须与标签格式一致，否则工作流会拒绝执行。

手动运行用于恢复失败的 Draft Release，不用于绕过版本、标签或 CI 校验。

需要验证裁剪构建时，在 `CI` 或 `Build Matrix` 工作流中选择 `Run workflow`，
并在 `tags` 中填写逗号分隔的组件标签，例如
`with_quic,with_vless,with_grpc,with_utls`。留空执行各目标支持的默认组件集。标签含义、
本地等价命令和许可边界见[构建脚本](../scripts/README.md#按组件标签编译)。
Build Matrix 的 `platforms` 可只重跑一个平台组；`macos` 会同时覆盖 Intel
和 Apple Silicon。
