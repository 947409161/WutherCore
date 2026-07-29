use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_WITH_EBPF");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    if std::env::var_os("CARGO_FEATURE_WITH_EBPF").is_none() {
        return Ok(());
    }
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if !matches!(target_os.as_str(), "linux" | "android") {
        anyhow::bail!("with_ebpf only supports Linux and Android targets");
    }

    let manifest_dir =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"));
    let program_dir = manifest_dir.join("ebpf");
    std::env::set_current_dir(&program_dir)?;
    let root_dir = program_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("eBPF program path is not UTF-8"))?;
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "core-inbound-ebpf",
            root_dir,
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
}
