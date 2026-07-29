//! wuther-core —— WutherCore 顶层 CLI。
//!
//! 子命令：
//! * `run -c <yaml>`：启动内核（Mixed 入站 + API + capture 诊断）。
//! * `check <yaml>`：仅做配置加载与编译，输出错误。
//! * `explain <yaml>`：输出编译后的 RuntimePlan（JSON，便于排错）。
//! * `migrate mihomo <old.yaml> -o <friendly.yaml>`：旧配置迁移。

mod host_resources;

use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use async_trait::async_trait;
use clap::{Parser, Subcommand, ValueEnum};
use comfy_table::{
    Attribute, Cell, CellAlignment, ColumnConstraint, ContentArrangement, Table, Width,
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL_CONDENSED,
};
#[cfg(feature = "with_api")]
use core_api::ApiServer;
use core_config::loader::load_from_path;
use core_feeds::{FeedDiskCache, FeedManager, FeedSink, FeedUpdate};
#[cfg(feature = "with_tun")]
use core_inbound::transparent as core_capture;
#[cfg(feature = "with_grpc")]
use core_inbound::{GrpcListener, run_grpc};
use core_inbound::{MixedListener, ensure_best_effort_privilege, run_mixed};
#[cfg(feature = "with_shadowsocks")]
use core_inbound::{ShadowsocksListenerHandle, start_shadowsocks_listeners};
#[cfg(feature = "with_xhttp")]
use core_inbound::{XhttpListenerHandle, start_xhttp_listeners};
#[cfg(feature = "with_wireguard")]
use core_outbound::proto::wireguard::{
    WireGuardServer, WireGuardServerConfig, WireGuardServerPeerConfig,
};
use core_ruleset::{RulesetManager, RulesetSpec, RulesetType};
use core_runtime::{Runtime, UrlTestConfig, UrlTester};
use core_store::{MultiprocessWal, Store, StoreOptions, TrafficTotalBlob};
use num_bigint::BigUint;
use tracing::{info, warn};

use crate::host_resources::listener_resource_claims;

#[derive(Parser, Debug)]
#[command(
    name = "wuther-core",
    version,
    about = "Modular cross-platform proxy core"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// 启动内核（前台运行）。
    Run {
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
    },
    /// 仅做配置校验。
    Check { config: PathBuf },
    /// 输出编译后的 RuntimePlan（JSON）。
    Explain { config: PathBuf },
    /// 配置迁移工具。
    Migrate {
        /// 源配置类型，目前支持 `mihomo`。
        kind: String,
        /// 输入文件路径。
        input: PathBuf,
        /// 输出 Friendly YAML 路径。
        #[arg(short, long)]
        output: PathBuf,
    },
    /// 订阅相关操作。
    Feeds {
        #[command(subcommand)]
        action: FeedsCmd,
    },
    /// 持久化 store 操作（节点学习数据、domain_best、pin、group manual 等）。
    Store {
        #[command(subcommand)]
        action: StoreCmd,
    },
    /// 查询持久化累计流量及完整分类。
    Traffic {
        /// Turso 数据库路径。
        #[arg(long)]
        path: Option<PathBuf>,
        /// 从正在运行的核心读取，例如 http://127.0.0.1:9090。
        #[arg(long)]
        api: Option<String>,
        /// 从配置解析 API 监听地址和密钥，适合自定义端口。
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// API 密钥。也可通过 WUTHERCORE_SECRET 环境变量提供。
        #[arg(long)]
        secret: Option<String>,
        /// 只显示指定分类，默认显示全部分类。
        #[arg(long, value_enum, default_value_t = TrafficCategory::All)]
        category: TrafficCategory,
        /// 每个分类显示的最大条目数，0 表示不限制。
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// 按哪个指标排序。
        #[arg(long, value_enum, default_value_t = TrafficSort::Total)]
        sort: TrafficSort,
        /// 显示完整十进制字节数。
        #[arg(long)]
        exact: bool,
        /// 输出机器可读 JSON，字节数始终为无损十进制字符串。
        #[arg(long)]
        json: bool,
    },
    /// 外部规则集操作（mihomo yaml/txt/list、sing-box json、自定义 payload）。
    Ruleset {
        #[command(subcommand)]
        action: RulesetCmd,
    },
    /// 显示当前二进制实际编译进入的组件标签。
    Components {
        /// 以 JSON 输出，便于脚本和部署系统读取。
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum RulesetCmd {
    /// 列出配置中所有规则集。
    List { config: PathBuf },
    /// 立刻拉取并解析所有规则集，输出条目数与匹配器统计。
    Refresh {
        config: PathBuf,
        #[arg(long, default_value = "data/rulesets")]
        cache_dir: PathBuf,
    },
    /// 双向转换：yaml/txt/list/json/rrs 互转（含 WutherCore 自研 RRS）。
    ///
    /// 例：
    ///   wuther-core ruleset convert geosite-cn.yaml geosite-cn.rrs
    ///   wuther-core ruleset convert ruleset.json ruleset.txt
    ///   wuther-core ruleset convert input.rrs output.yaml --output-format yaml
    Convert {
        /// 输入文件路径。
        input: PathBuf,
        /// 输出文件路径；输出格式按扩展名自动识别，可被 --output-format 覆盖。
        output: PathBuf,
        /// 显式指定输入格式（yaml/txt/json/rrs/mrs/srs）；缺省时自动嗅探。
        #[arg(long)]
        input_format: Option<String>,
        /// 显式指定输出格式（yaml/txt/json/rrs）；缺省时按 output 扩展名。
        #[arg(long)]
        output_format: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum StoreCmd {
    /// 显示 store 路径、大小与各表行数。
    Info {
        /// 显式指定 Turso 数据库路径，优先于配置文件。
        #[arg(long)]
        path: Option<PathBuf>,
        /// 从配置文件读取完整 database 设置。
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    /// 清空所有学习数据（保留 schema 版本）。
    Reset {
        /// 显式指定 Turso 数据库路径，优先于配置文件。
        #[arg(long)]
        path: Option<PathBuf>,
        /// 从配置文件读取完整 database 设置。
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TrafficCategory {
    All,
    Network,
    Inbound,
    InboundType,
    InboundUser,
    Outbound,
    Group,
    Provider,
    Rule,
    RulePayload,
    Process,
    Destination,
    DestinationPort,
    Source,
    SourceGeoip,
    DestinationGeoip,
    SourceAsn,
    DestinationAsn,
    Uid,
}

impl TrafficCategory {
    fn dimension(self) -> Option<&'static str> {
        Some(match self {
            Self::All => return None,
            Self::Network => "network",
            Self::Inbound => "inbound",
            Self::InboundType => "inbound_type",
            Self::InboundUser => "inbound_user",
            Self::Outbound => "outbound",
            Self::Group => "group",
            Self::Provider => "provider",
            Self::Rule => "rule",
            Self::RulePayload => "rule_payload",
            Self::Process => "process",
            Self::Destination => "destination",
            Self::DestinationPort => "destination_port",
            Self::Source => "source",
            Self::SourceGeoip => "source_geoip",
            Self::DestinationGeoip => "destination_geoip",
            Self::SourceAsn => "source_asn",
            Self::DestinationAsn => "destination_asn",
            Self::Uid => "uid",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TrafficSort {
    Total,
    Upload,
    Download,
    Connections,
    Name,
}

#[derive(Subcommand, Debug)]
enum FeedsCmd {
    /// 列出配置中所有订阅源。
    List { config: PathBuf },
    /// 立刻拉取并解析所有订阅，输出节点统计；不启动内核。
    Refresh {
        config: PathBuf,
        /// 缓存目录（默认 ./data/feeds）
        #[arg(long, default_value = "data/feeds")]
        cache_dir: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    // 进程级 rustls 加密提供者注册 —— **必须在任何 ClientConfig::builder() 调用之前**。
    // rustls 0.23 在多个依赖（quinn / hickory-resolver / reqwest）同时启用时，
    // 全局默认 CryptoProvider 会变得"模糊"：未显式安装时 builder() 会 panic
    // ("no process-level CryptoProvider available")，所有 TLS 出站直接死锁，
    // URLTest 的现象就是 30 个节点全 5005ms 超时。
    // 使用 ring 作为唯一安装的提供者；已安装时返回 Err，忽略即可。
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    if !matches!(&cli.cmd, Cmd::Run { .. }) {
        core_observe::init_tracing();
    }
    match cli.cmd {
        Cmd::Run { config } => {
            let rt = build_multi_thread_runtime()?;
            rt.block_on(cmd_run(config))
        }
        Cmd::Check { config } => cmd_check(config),
        Cmd::Explain { config } => cmd_explain(config),
        Cmd::Migrate {
            kind,
            input,
            output,
        } => cmd_migrate(kind, input, output),
        Cmd::Feeds { action } => {
            let rt = build_multi_thread_runtime()?;
            rt.block_on(cmd_feeds(action))
        }
        Cmd::Store { action } => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(cmd_store(action))
        }
        Cmd::Traffic {
            path,
            api,
            config,
            secret,
            category,
            top,
            sort,
            exact,
            json,
        } => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(cmd_traffic(
                path, api, config, secret, category, top, sort, exact, json,
            ))
        }
        Cmd::Ruleset { action } => {
            let rt = build_multi_thread_runtime()?;
            rt.block_on(cmd_ruleset(action))
        }
        Cmd::Components { json } => cmd_components(json),
    }
}

fn build_multi_thread_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .enable_all()
        .thread_name("wuther-worker")
        // Bound blocking expansion. Network connects no longer use this pool;
        // it remains available for filesystem and resolver implementations.
        .max_blocking_threads(128)
        // Drain a substantial ready-I/O batch per reactor turn while retaining
        // Tokio's cooperative task scheduling.
        .max_io_events_per_tick(1024);
    #[cfg(target_os = "android")]
    {
        // Android commonly reports every big.LITTLE CPU. Driving one runtime
        // thread per logical CPU increases migrations and heat for a proxy
        // workload whose hot path is asynchronous I/O.
        let workers = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(2)
            .clamp(2, 4);
        builder.worker_threads(workers);
    }
    builder.build()
}

fn compiled_component_tags() -> Vec<&'static str> {
    let mut tags = Vec::new();
    macro_rules! push_tag {
        ($feature:literal) => {
            if cfg!(feature = $feature) {
                tags.push($feature);
            }
        };
    }
    push_tag!("with_api");
    push_tag!("with_tun");
    push_tag!("with_anytls");
    push_tag!("with_grpc");
    push_tag!("with_hysteria");
    push_tag!("with_hysteria2");
    push_tag!("with_http");
    push_tag!("with_http_transport");
    push_tag!("with_mieru");
    push_tag!("with_naive");
    push_tag!("with_quic");
    push_tag!("with_reality");
    push_tag!("with_shadowsocks");
    push_tag!("with_shadowsocksr");
    push_tag!("with_snell");
    push_tag!("with_socks");
    push_tag!("with_ssh");
    push_tag!("with_sudoku");
    push_tag!("with_trojan");
    push_tag!("with_trusttunnel");
    push_tag!("with_tuic");
    push_tag!("with_utls");
    push_tag!("with_vless");
    push_tag!("with_vmess");
    push_tag!("with_wireguard");
    push_tag!("with_ws");
    push_tag!("with_xhttp");
    push_tag!("with_young");
    tags
}

fn cmd_components(json: bool) -> anyhow::Result<()> {
    let tags = compiled_component_tags();
    if json {
        println!("{}", serde_json::to_string_pretty(&tags)?);
    } else if tags.is_empty() {
        println!("minimal (no optional component tags)");
    } else {
        println!("{}", tags.join(","));
    }
    Ok(())
}

fn validate_compiled_components(
    plan: &core_config::runtime_plan::RuntimePlan,
) -> anyhow::Result<()> {
    for node in &plan.nodes {
        core_outbound::registry::validate_node_components(node).map_err(|error| {
            anyhow::anyhow!(
                "node `{}` requires an omitted component: {error}",
                node.name
            )
        })?;
    }

    macro_rules! require_empty {
        ($enabled:expr, $value:expr, $name:literal, $tag:literal) => {
            if !$enabled && !$value.is_empty() {
                anyhow::bail!(
                    "{} is configured but not compiled in; rebuild with `{}`",
                    $name,
                    $tag
                );
            }
        };
    }
    require_empty!(
        cfg!(feature = "with_grpc"),
        plan.listen.grpc,
        "gRPC inbound",
        "with_grpc"
    );
    require_empty!(
        cfg!(feature = "with_xhttp"),
        plan.listen.xhttp,
        "XHTTP inbound",
        "with_xhttp"
    );
    require_empty!(
        cfg!(feature = "with_shadowsocks"),
        plan.listen.shadowsocks,
        "Shadowsocks inbound",
        "with_shadowsocks"
    );
    require_empty!(
        cfg!(feature = "with_wireguard"),
        plan.listen.wireguard,
        "WireGuard inbound",
        "with_wireguard"
    );
    require_empty!(
        cfg!(feature = "with_young"),
        plan.listen.young,
        "Young inbound",
        "with_young"
    );
    require_empty!(
        cfg!(feature = "with_reality"),
        plan.listen.reality,
        "REALITY inbound",
        "with_reality"
    );
    if plan.capture.on && !cfg!(feature = "with_tun") {
        anyhow::bail!("capture/TUN is configured but not compiled in; rebuild with `with_tun`");
    }
    if plan.ui.on && !cfg!(feature = "with_api") {
        anyhow::bail!("API/UI is configured but not compiled in; rebuild with `with_api`");
    }
    Ok(())
}

async fn cmd_ruleset(action: RulesetCmd) -> anyhow::Result<()> {
    match action {
        RulesetCmd::List { config } => {
            let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
            if plan.route.sets.is_empty() {
                println!("配置中未声明 route.sets");
                return Ok(());
            }
            for (name, s) in &plan.route.sets {
                let src = s
                    .url
                    .clone()
                    .or_else(|| s.path.clone())
                    .unwrap_or_else(|| format!("payload({} 行)", s.payload.len()));
                println!(
                    "{name:>20}  type={}  format={}  every={:?}  src={}",
                    s.r#type,
                    s.format.as_deref().unwrap_or("auto"),
                    s.every,
                    src
                );
            }
            Ok(())
        }
        RulesetCmd::Refresh { config, cache_dir } => {
            let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
            if plan.route.sets.is_empty() {
                println!("配置中未声明 route.sets");
                return Ok(());
            }
            let specs = build_ruleset_specs(&plan.route.sets);
            let idx = core_ruleset::RulesetIndex::new();
            let mgr = RulesetManager::new(specs.clone(), Some(cache_dir), idx.clone());
            for (name, spec) in &specs {
                match mgr.refresh_once(name, spec).await {
                    Ok(u) => {
                        println!(
                            "{name:>20}  {} 条 {}",
                            u.size,
                            if u.from_cache { "(cache)" } else { "(online)" }
                        );
                        if let Some(m) = idx.get(name) {
                            let s = m.stats();
                            println!(
                                "    domains={} suffixes={} keywords={} regex={} cidr_v4={} cidr_v6={} ports={} processes={}",
                                s.domains,
                                s.suffixes,
                                s.keywords,
                                s.regex,
                                s.cidr_v4,
                                s.cidr_v6,
                                s.ports,
                                s.processes
                            );
                        }
                    }
                    Err(e) => println!("{name:>20}  FAILED: {e}"),
                }
            }
            Ok(())
        }
        RulesetCmd::Convert {
            input,
            output,
            input_format,
            output_format,
        } => {
            let body = std::fs::read(&input).context("read input")?;
            let in_path = input.to_string_lossy().to_string();
            let in_fmt =
                core_ruleset::detect_format(input_format.as_deref(), Some(&in_path), &body);
            let entries = core_ruleset::parse_ruleset(in_fmt, &body)
                .map_err(|e| anyhow::anyhow!("解析失败 ({:?}): {e}", in_fmt))?;
            let out_fmt = output_format
                .as_deref()
                .or_else(|| output.extension().and_then(|e| e.to_str()))
                .unwrap_or("rrs")
                .to_ascii_lowercase();
            let out_bytes: Vec<u8> = match out_fmt.as_str() {
                "rrs" | "wuthercore" => core_ruleset::rrs::encode(&entries),
                "yaml" | "yml" => core_ruleset::rrs::entries_to_yaml(&entries).into_bytes(),
                "txt" | "list" | "text" => core_ruleset::rrs::entries_to_txt(&entries).into_bytes(),
                "json" | "singbox" | "sing-box" => {
                    core_ruleset::rrs::entries_to_singbox_json(&entries)
                        .map_err(anyhow::Error::msg)?
                        .into_bytes()
                }
                other => {
                    anyhow::bail!("不支持的输出格式 \"{other}\"；支持：yaml / txt / json / rrs")
                }
            };
            std::fs::write(&output, &out_bytes).context("write output")?;
            println!(
                "已转换：{} ({}) → {} ({}) | {} 条规则 | 输入 {} bytes → 输出 {} bytes",
                input.display(),
                format_label(in_fmt),
                output.display(),
                out_fmt,
                entries.len(),
                body.len(),
                out_bytes.len()
            );
            Ok(())
        }
    }
}

/// 把 [`core_config::model::RuleSetSpec`]（YAML 反序列化产物）翻译成
/// [`core_ruleset::RulesetSpec`] —— `cmd_ruleset` Refresh 子命令与 `cmd_run`
/// 启动路径共用此函数，避免字段对应散落两份。
fn build_ruleset_specs(
    sets: &std::collections::BTreeMap<String, core_config::model::RuleSetSpec>,
) -> std::collections::BTreeMap<String, RulesetSpec> {
    sets.iter()
        .map(|(name, s)| {
            let typ = match s.r#type.to_ascii_lowercase().as_str() {
                "ipcidr" | "ip" => RulesetType::Ipcidr,
                "classical" => RulesetType::Classical,
                "mixed" => RulesetType::Mixed,
                _ => RulesetType::Domain,
            };
            (
                name.clone(),
                RulesetSpec {
                    url: s.url.clone(),
                    path: s.path.clone(),
                    payload: s.payload.clone(),
                    r#type: typ,
                    format: s.format.clone(),
                    every: s.every,
                    via: s.via.clone(),
                },
            )
        })
        .collect()
}

fn format_label(f: core_ruleset::RulesetFormat) -> &'static str {
    use core_ruleset::RulesetFormat::*;
    match f {
        Yaml => "yaml",
        Text => "txt",
        SingboxJson => "json",
        Mrs => "mrs",
        Srs => "srs",
        Rrs => "rrs",
        Unknown => "?",
    }
}

#[derive(Debug, Clone)]
struct TrafficRow {
    blob: TrafficTotalBlob,
    upload: BigUint,
    download: BigUint,
    total: BigUint,
}

const TRAFFIC_DIMENSIONS: &[&str] = &[
    "network",
    "inbound",
    "inbound_type",
    "inbound_user",
    "outbound",
    "group",
    "provider",
    "rule",
    "rule_payload",
    "process",
    "destination",
    "destination_port",
    "source",
    "source_geoip",
    "destination_geoip",
    "source_asn",
    "destination_asn",
    "uid",
];

async fn cmd_traffic(
    path: Option<PathBuf>,
    api: Option<String>,
    config: Option<PathBuf>,
    secret: Option<String>,
    category: TrafficCategory,
    top: usize,
    sort: TrafficSort,
    exact: bool,
    json: bool,
) -> anyhow::Result<()> {
    let config_was_provided = config.is_some();
    let (config_api, config_secret, config_store) = if let Some(config) = config {
        let plan = load_from_path(&config).map_err(|error| anyhow::anyhow!("{error}"))?;
        let config_api = plan.listen.panel.as_ref().map(|panel| {
            let host = match panel.host.as_str() {
                "0.0.0.0" => "127.0.0.1".to_string(),
                "::" | "[::]" => "[::1]".to_string(),
                host if host.contains(':') && !host.starts_with('[') => format!("[{host}]"),
                host => host.to_string(),
            };
            format!("http://{host}:{}", panel.port)
        });
        let config_store = plan
            .database
            .enabled
            .then(|| store_options_from_config(&plan.database));
        (config_api, plan.ui.secret.clone(), config_store)
    } else {
        (None, None, None)
    };
    let api = api.or(config_api);
    let secret = secret
        .or_else(|| std::env::var("WUTHERCORE_SECRET").ok())
        .or(config_secret);
    let store_options = match (path, config_store) {
        (Some(path), Some(mut options)) => {
            options.path = path;
            Some(options)
        }
        (Some(path), None) => Some(StoreOptions::new(path)),
        (None, Some(options)) => Some(options),
        (None, None) if !config_was_provided => Some(StoreOptions::new("data/state/wuthercore.db")),
        (None, None) => None,
    };

    let (source, saved) =
        if let Some(options) = store_options.filter(|options| options.path.exists()) {
            match Store::read_traffic_totals_with_options(options.clone()).await {
                Ok(rows) => (
                    options.path.display().to_string(),
                    rows.into_iter().map(|(_, blob)| blob).collect(),
                ),
                Err(error) => {
                    let fallback_api = api.as_deref().unwrap_or("http://127.0.0.1:9090");
                    fetch_live_traffic(fallback_api, secret.as_deref())
                    .await
                    .map_err(|api_error| {
                        anyhow::anyhow!(
                            "直接读取 Turso 数据库失败: {error}\n读取核心快照也失败: {api_error}\n\
                             自定义监听地址请传 --config <FILE> 或 --api <URL>"
                        )
                    })?
                }
            }
        } else if let Some(api) = api {
            fetch_live_traffic(&api, secret.as_deref()).await?
        } else {
            anyhow::bail!("流量数据库不存在，并且没有可用的核心 API");
        };
    let mut rows = Vec::with_capacity(saved.len());
    for blob in saved {
        let upload = parse_traffic_integer(&blob.upload)
            .with_context(|| format!("无效的上传累计值: {} / {}", blob.dimension, blob.label))?;
        let download = parse_traffic_integer(&blob.download)
            .with_context(|| format!("无效的下载累计值: {} / {}", blob.dimension, blob.label))?;
        let total = &upload + &download;
        rows.push(TrafficRow {
            blob,
            upload,
            download,
            total,
        });
    }

    let total = rows
        .iter()
        .find(|row| row.blob.dimension == "total" && row.blob.label == "all")
        .cloned()
        .unwrap_or_else(|| TrafficRow {
            blob: TrafficTotalBlob {
                dimension: "total".into(),
                label: "all".into(),
                upload: "0".into(),
                download: "0".into(),
                ..TrafficTotalBlob::default()
            },
            upload: BigUint::default(),
            download: BigUint::default(),
            total: BigUint::default(),
        });

    if json {
        return print_traffic_json(&source, &rows, &total, category, top, sort);
    }

    println!("WutherCore 持久流量汇总");
    println!(
        "{}",
        render_traffic_summary_table(&source, &total, exact, None)
    );

    let dimensions: Vec<&str> = match category.dimension() {
        Some(dimension) => vec![dimension],
        None => TRAFFIC_DIMENSIONS.to_vec(),
    };
    for dimension in dimensions {
        let selected = sorted_traffic_rows(&rows, dimension, sort, top);
        if selected.is_empty() {
            continue;
        }
        println!();
        println!("{}", traffic_dimension_title(dimension));
        println!(
            "{}",
            render_traffic_dimension_table(&selected, &total, exact, None)
        );
    }
    Ok(())
}

async fn fetch_live_traffic(
    api: &str,
    secret: Option<&str>,
) -> anyhow::Result<(String, Vec<TrafficTotalBlob>)> {
    let base = api.trim().trim_end_matches('/');
    let endpoint = if base.ends_with("/traffic/summary") {
        base.to_string()
    } else if base.ends_with("/v1") {
        format!("{base}/traffic/summary")
    } else {
        format!("{base}/v1/traffic/summary")
    };
    let mut options = core_fetch::FetchOptions {
        accept_encoding: false,
        max_body_bytes: 64 * 1024 * 1024,
        ..core_fetch::FetchOptions::default()
    };
    if let Some(secret) = secret.filter(|secret| !secret.is_empty()) {
        options
            .headers
            .push(("Authorization".into(), format!("Bearer {secret}")));
    }
    let response = core_fetch::fetch(&endpoint, &options)
        .await
        .with_context(|| format!("无法读取运行中核心的流量汇总: {endpoint}"))?;
    let body: serde_json::Value =
        serde_json::from_slice(&response.bytes).context("流量汇总 API 返回了无效 JSON")?;
    let totals = body
        .get("totals")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("流量汇总 API 缺少 totals 字段"))?;
    let rows = serde_json::from_value::<Vec<TrafficTotalBlob>>(totals)
        .context("流量汇总 API 的 totals 格式无效")?;
    Ok((endpoint, rows))
}

fn print_traffic_json(
    source: &str,
    rows: &[TrafficRow],
    total: &TrafficRow,
    category: TrafficCategory,
    top: usize,
    sort: TrafficSort,
) -> anyhow::Result<()> {
    let dimensions: Vec<&str> = match category.dimension() {
        Some(dimension) => vec![dimension],
        None => TRAFFIC_DIMENSIONS.to_vec(),
    };
    let mut categories = serde_json::Map::new();
    for dimension in dimensions {
        let selected = sorted_traffic_rows(rows, dimension, sort, top);
        if selected.is_empty() {
            continue;
        }
        categories.insert(
            dimension.to_string(),
            serde_json::Value::Array(selected.into_iter().map(traffic_row_json).collect()),
        );
    }
    let output = serde_json::json!({
        "source": source,
        "generatedAt": now_epoch_secs(),
        "total": traffic_row_json(total),
        "categories": categories,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn traffic_row_json(row: &TrafficRow) -> serde_json::Value {
    serde_json::json!({
        "dimension": row.blob.dimension,
        "label": row.blob.label,
        "upload": row.upload.to_str_radix(10),
        "download": row.download.to_str_radix(10),
        "total": row.total.to_str_radix(10),
        "uploadFormatted": format_big_bytes(&row.upload),
        "downloadFormatted": format_big_bytes(&row.download),
        "totalFormatted": format_big_bytes(&row.total),
        "connections": row.blob.connections,
        "firstSeen": row.blob.first_seen_secs,
        "lastSeen": row.blob.last_seen_secs,
    })
}

fn sorted_traffic_rows<'a>(
    rows: &'a [TrafficRow],
    dimension: &str,
    sort: TrafficSort,
    top: usize,
) -> Vec<&'a TrafficRow> {
    let mut selected = rows
        .iter()
        .filter(|row| row.blob.dimension == dimension)
        .collect::<Vec<_>>();
    selected.sort_by(|a, b| {
        let order = match sort {
            TrafficSort::Total => b.total.cmp(&a.total),
            TrafficSort::Upload => b.upload.cmp(&a.upload),
            TrafficSort::Download => b.download.cmp(&a.download),
            TrafficSort::Connections => b.blob.connections.cmp(&a.blob.connections),
            TrafficSort::Name => a.blob.label.cmp(&b.blob.label),
        };
        order.then_with(|| a.blob.label.cmp(&b.blob.label))
    });
    if top != 0 {
        selected.truncate(top);
    }
    selected
}

fn parse_traffic_integer(value: &str) -> anyhow::Result<BigUint> {
    BigUint::parse_bytes(value.as_bytes(), 10).ok_or_else(|| anyhow::anyhow!("不是非负十进制整数"))
}

/// 1024 进制的人类可读格式。单位最多显示为 BB，但数值本身继续任意增长。
fn format_big_bytes(value: &BigUint) -> String {
    const UNITS: [&str; 10] = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB", "BB"];
    let base = BigUint::from(1024u16);
    let mut unit = 0usize;
    let mut divisor = BigUint::from(1u8);
    while unit + 1 < UNITS.len() {
        let next = &divisor * &base;
        if value < &next {
            break;
        }
        divisor = next;
        unit += 1;
    }
    if unit == 0 {
        return format!("{} B", value.to_str_radix(10));
    }

    let whole = value / &divisor;
    let remainder = value % &divisor;
    let fraction = ((remainder * 100u8) / &divisor)
        .to_u64_digits()
        .first()
        .copied()
        .unwrap_or(0);
    if whole >= BigUint::from(100u8) || fraction == 0 {
        format!("{} {}", whole.to_str_radix(10), UNITS[unit])
    } else if whole >= BigUint::from(10u8) {
        format!(
            "{}.{} {}",
            whole.to_str_radix(10),
            fraction / 10,
            UNITS[unit]
        )
    } else {
        format!("{}.{:02} {}", whole.to_str_radix(10), fraction, UNITS[unit])
    }
}

fn format_traffic_value(value: &BigUint, exact: bool) -> String {
    if exact {
        format!("{} B", format_decimal_grouped(&value.to_str_radix(10)))
    } else {
        format_big_bytes(value)
    }
}

fn traffic_percentage(value: &BigUint, total: &BigUint) -> String {
    if total == &BigUint::default() {
        return "0.00%".into();
    }
    let basis_points = ((value * 10_000u16) / total)
        .to_u64_digits()
        .first()
        .copied()
        .unwrap_or(0);
    format!("{}.{:02}%", basis_points / 100, basis_points % 100)
}

fn format_decimal_grouped(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + value.len() / 3);
    let first = value.len() % 3;
    for (index, ch) in value.chars().enumerate() {
        if index != 0 && (index == first || (index > first && (index - first) % 3 == 0)) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn traffic_table(width_override: Option<u16>) -> (Table, u16) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_truncation_indicator("…");

    // Comfy Table detects the terminal width itself. A deterministic fallback
    // keeps redirected output bounded, while the cap avoids unreadably wide
    // tables on ultrawide terminals.
    let width = width_override
        .or_else(|| table.width())
        .unwrap_or(120)
        .clamp(20, 160);
    table.set_width(width);
    (table, width)
}

fn traffic_header(value: &str) -> Cell {
    Cell::new(value).add_attribute(Attribute::Bold)
}

fn render_traffic_summary_table(
    source: &str,
    total: &TrafficRow,
    exact: bool,
    width_override: Option<u16>,
) -> String {
    let (mut table, _) = traffic_table(width_override);
    table.set_header([traffic_header("统计项"), traffic_header("数值")]);
    table.add_row([Cell::new("数据源"), Cell::new(source)]);
    if total.blob.first_seen_secs != 0 {
        table.add_row([
            Cell::new("统计区间"),
            Cell::new(format!(
                "{} 至 {}",
                format_epoch(total.blob.first_seen_secs),
                format_epoch(total.blob.last_seen_secs)
            )),
        ]);
    }
    table.add_row([
        Cell::new("累计上传"),
        Cell::new(format_traffic_value(&total.upload, exact)),
    ]);
    table.add_row([
        Cell::new("累计下载"),
        Cell::new(format_traffic_value(&total.download, exact)),
    ]);
    table.add_row([
        Cell::new("累计总量").add_attribute(Attribute::Bold),
        Cell::new(format_traffic_value(&total.total, exact)).add_attribute(Attribute::Bold),
    ]);
    table.add_row([
        Cell::new("连接次数"),
        Cell::new(format_decimal_grouped(&total.blob.connections.to_string())),
    ]);

    if let Some(column) = table.column_mut(0) {
        column.set_constraint(ColumnConstraint::Absolute(Width::Fixed(12)));
    }
    table.to_string()
}

fn render_traffic_dimension_table(
    rows: &[&TrafficRow],
    total: &TrafficRow,
    exact: bool,
    width_override: Option<u16>,
) -> String {
    let (mut table, width) = traffic_table(width_override);
    if width >= 110 {
        table.set_header([
            traffic_header("名称"),
            traffic_header("上传"),
            traffic_header("下载"),
            traffic_header("总量"),
            traffic_header("占比"),
            traffic_header("连接"),
        ]);
        for row in rows {
            table.add_row([
                Cell::new(&row.blob.label),
                Cell::new(format_traffic_value(&row.upload, exact)),
                Cell::new(format_traffic_value(&row.download, exact)),
                Cell::new(format_traffic_value(&row.total, exact)),
                Cell::new(traffic_percentage(&row.total, &total.total)),
                Cell::new(format_decimal_grouped(&row.blob.connections.to_string())),
            ]);
        }
        if let Some(column) = table.column_mut(0) {
            column.set_constraint(ColumnConstraint::UpperBoundary(Width::Percentage(35)));
        }
        for index in 1..6 {
            if let Some(column) = table.column_mut(index) {
                column.set_cell_alignment(CellAlignment::Right);
            }
        }
    } else if width >= 60 {
        table.set_header([
            traffic_header("名称"),
            traffic_header("流量"),
            traffic_header("占比"),
            traffic_header("连接"),
        ]);
        for row in rows {
            table.add_row([
                Cell::new(&row.blob.label),
                Cell::new(format!(
                    "上传 {}\n下载 {}\n总量 {}",
                    format_traffic_value(&row.upload, exact),
                    format_traffic_value(&row.download, exact),
                    format_traffic_value(&row.total, exact)
                )),
                Cell::new(traffic_percentage(&row.total, &total.total)),
                Cell::new(format_decimal_grouped(&row.blob.connections.to_string())),
            ]);
        }
        if let Some(column) = table.column_mut(0) {
            column.set_constraint(ColumnConstraint::UpperBoundary(Width::Percentage(40)));
        }
        for index in 1..4 {
            if let Some(column) = table.column_mut(index) {
                column.set_cell_alignment(CellAlignment::Right);
            }
        }
    } else {
        table.set_header([traffic_header("名称"), traffic_header("明细")]);
        for row in rows {
            table.add_row([
                Cell::new(&row.blob.label),
                Cell::new(format!(
                    "上传 {}\n下载 {}\n总量 {}\n占比 {}\n连接 {}",
                    format_traffic_value(&row.upload, exact),
                    format_traffic_value(&row.download, exact),
                    format_traffic_value(&row.total, exact),
                    traffic_percentage(&row.total, &total.total),
                    format_decimal_grouped(&row.blob.connections.to_string())
                )),
            ]);
        }
        if let Some(column) = table.column_mut(0) {
            column.set_constraint(ColumnConstraint::UpperBoundary(Width::Percentage(42)));
        }
        if let Some(column) = table.column_mut(1) {
            column.set_cell_alignment(CellAlignment::Right);
        }
    }
    table.to_string()
}

fn traffic_dimension_title(dimension: &str) -> &'static str {
    match dimension {
        "network" => "按网络协议",
        "inbound" => "按入站",
        "inbound_type" => "按入站类型",
        "inbound_user" => "按入站用户",
        "outbound" => "按出站节点",
        "group" => "按策略组",
        "provider" => "按远程订阅",
        "rule" => "按匹配规则",
        "rule_payload" => "按规则内容",
        "process" => "按进程",
        "destination" => "按目标地址",
        "destination_port" => "按目标端口",
        "source" => "按来源地址",
        "source_geoip" => "按来源地区",
        "destination_geoip" => "按目标地区",
        "source_asn" => "按来源 ASN",
        "destination_asn" => "按目标 ASN",
        "uid" => "按用户 UID",
        _ => "其他分类",
    }
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn format_epoch(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let day_seconds = seconds % 86_400;
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u64, u64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u64, day as u64)
}

async fn cmd_store(action: StoreCmd) -> anyhow::Result<()> {
    match action {
        StoreCmd::Info { path, config } => {
            let options = resolve_store_options(path, config)?;
            if !options.path.exists() {
                println!("store 不存在：{}", options.path.display());
                return Ok(());
            }
            let s = Store::open_with_options(options)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let st = s
                .approximate_stats()
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("store: {}", st.path);
            println!("  size:              {} bytes", st.size_bytes);
            println!("  smart_node_stats:  {}", st.smart_node_stats);
            println!("  smart_domain_best: {}", st.smart_domain_best);
            println!("  smart_negative:    {}", st.smart_negative);
            println!("  smart_pin:         {}", st.smart_pin);
            println!("  group_manual:      {}", st.group_manual);
            println!("  feed_meta:         {}", st.feed_meta);
            println!("  dns_cache:         {}", st.dns_cache);
            println!("  traffic_totals:    {}", st.traffic_totals);
            Ok(())
        }
        StoreCmd::Reset { path, config } => {
            let options = resolve_store_options(path, config)?;
            if !options.path.exists() {
                println!("store 不存在：{}", options.path.display());
                return Ok(());
            }
            let database_path = options.path.clone();
            let s = Store::open_with_options(options)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            s.reset().await.map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("已清空所有学习数据：{}", database_path.display());
            Ok(())
        }
    }
}

fn resolve_store_options(
    path: Option<PathBuf>,
    config: Option<PathBuf>,
) -> anyhow::Result<StoreOptions> {
    let configured = if let Some(config_path) = config {
        let plan = load_from_path(&config_path).map_err(|error| anyhow::anyhow!("{error}"))?;
        if !plan.database.enabled && path.is_none() {
            anyhow::bail!("配置 {} 已禁用 database", config_path.display());
        }
        Some(store_options_from_config(&plan.database))
    } else {
        None
    };

    match (path, configured) {
        (Some(path), Some(mut options)) => {
            options.path = path;
            Ok(options)
        }
        (Some(path), None) => Ok(StoreOptions::new(path)),
        (None, Some(options)) => Ok(options),
        (None, None) => Ok(StoreOptions::new("data/state/wuthercore.db")),
    }
}

fn store_options_from_config(config: &core_config::model::DatabaseConfig) -> StoreOptions {
    StoreOptions {
        path: config.path.clone(),
        busy_timeout: config.busy_timeout,
        max_write_attempts: config.max_write_attempts,
        multiprocess_wal: match config.multiprocess_wal {
            core_config::model::MultiprocessWalMode::Auto => MultiprocessWal::Auto,
            core_config::model::MultiprocessWalMode::On => MultiprocessWal::Enabled,
            core_config::model::MultiprocessWalMode::Off => MultiprocessWal::Disabled,
        },
        experimental_vacuum: config.experimental_vacuum,
    }
}

async fn cmd_feeds(action: FeedsCmd) -> anyhow::Result<()> {
    match action {
        FeedsCmd::List { config } => {
            let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
            for (name, d) in &plan.feeds {
                println!(
                    "{name:>20}  url={}  every={:?}  via={}",
                    d.url, d.every, d.via
                );
            }
            Ok(())
        }
        FeedsCmd::Refresh { config, cache_dir } => {
            let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
            if plan.feeds.is_empty() {
                println!("配置中没有 feeds，跳过");
                return Ok(());
            }
            let cache = FeedDiskCache::new(&cache_dir).context("create feed cache")?;
            let mgr = FeedManager::new(plan.feeds.clone(), Some(cache));
            for (name, detail) in &plan.feeds {
                match mgr
                    .refresh_once(name, detail, std::time::Duration::from_secs(30))
                    .await
                {
                    Ok(update) => {
                        println!(
                            "{name:>20}  {} 个节点  {} bytes  {}",
                            update.nodes.len(),
                            update.raw_bytes,
                            if update.from_cache {
                                "(disk-cache)"
                            } else {
                                "(online)"
                            }
                        );
                        for n in update.nodes.iter().take(5) {
                            println!(
                                "    - {} [{}://{}:{}]",
                                n.name,
                                n.protocol.as_str(),
                                n.host,
                                n.port
                            );
                        }
                        if update.nodes.len() > 5 {
                            println!("    ... 还有 {} 个", update.nodes.len() - 5);
                        }
                    }
                    Err(e) => println!("{name:>20}  FAILED: {e}"),
                }
            }
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "with_tun"))]
mod tests {
    use core_config::model::{Log, LogFile, LogFormat, LogLevel};

    use super::*;

    #[test]
    fn user_log_config_maps_to_observe_tracing_config() {
        let log = Log {
            on: true,
            level: LogLevel::Debug,
            filter: Some("info,capture::traffic=trace".into()),
            stdout: false,
            file: LogFile {
                on: true,
                path: "data/logs/custom.log".into(),
            },
            format: LogFormat::Json,
            connection_summary_interval: std::time::Duration::ZERO,
        };

        let tracing = tracing_config_from_user_log(&log);

        assert!(tracing.enabled);
        assert_eq!(tracing.level, "debug");
        assert_eq!(
            tracing.filter.as_deref(),
            Some("info,capture::traffic=trace")
        );
        assert!(!tracing.stdout);
        assert_eq!(tracing.format, core_observe::TracingFormat::Json);
        let file = tracing.file.expect("file sink enabled");
        assert!(file.enabled);
        assert_eq!(file.path, PathBuf::from("data/logs/custom.log"));
    }

    #[test]
    fn log_off_disables_observe_tracing_even_if_sinks_are_set() {
        let log = Log {
            on: false,
            level: LogLevel::Trace,
            filter: None,
            stdout: true,
            file: LogFile {
                on: true,
                path: "data/logs/custom.log".into(),
            },
            format: LogFormat::Text,
            connection_summary_interval: std::time::Duration::ZERO,
        };

        let tracing = tracing_config_from_user_log(&log);

        assert!(!tracing.enabled);
        assert!(tracing.stdout);
        assert!(tracing.file.is_some());
    }

    #[tokio::test]
    async fn ruleset_ipset_provider_publishes_atomic_versioned_prefixes() {
        let index = core_ruleset::RulesetIndex::new();
        index.declare(["geoip-cn", "not-ready"]);
        let provider = RulesetIpSetProvider {
            index: index.clone(),
        };
        let names = vec![
            "geoip-cn".to_string(),
            "not-ready".to_string(),
            "missing".to_string(),
            "geoip-cn".to_string(),
        ];

        let (initial, mut updates) =
            core_capture::IpSetProvider::prefix_snapshot_and_subscribe(&provider, &names).unwrap();
        assert_eq!(initial.revision, *updates.borrow());
        assert_eq!(initial.sets.len(), 3);
        assert!(matches!(
            initial.sets[0].status,
            core_capture::IpSetPrefixStatus::Pending
        ));
        assert!(matches!(
            initial.sets[2].status,
            core_capture::IpSetPrefixStatus::Missing
        ));

        index.insert(Arc::new(core_ruleset::RulesetMatcher::compile_ipcidr(
            "geoip-cn",
            [
                "10.0.0.0/9".to_string(),
                "10.128.0.0/9".to_string(),
                "2001:db8::/32".to_string(),
            ],
        )));
        tokio::time::timeout(std::time::Duration::from_secs(1), updates.changed())
            .await
            .expect("prefix update should wake subscriber")
            .expect("ruleset index keeps the watch sender alive");

        let current = core_capture::IpSetProvider::prefix_snapshot(&provider, &names).unwrap();
        assert_eq!(current.revision, *updates.borrow());
        assert_eq!(
            current.sets[0].status,
            core_capture::IpSetPrefixStatus::Ready {
                semantics: core_capture::IpSetPrefixSemantics::Exact,
            }
        );
        assert_eq!(
            current.sets[0].ipv4.as_ref(),
            &["10.0.0.0/8".parse().unwrap()]
        );
        assert_eq!(
            current.sets[0].ipv6.as_ref(),
            &["2001:db8::/32".parse().unwrap()]
        );

        let unchanged_revision = current.revision;
        index.insert(Arc::new(core_ruleset::RulesetMatcher::compile_ipcidr(
            "geoip-cn",
            ["2001:db8::/32".to_string(), "10.0.0.0/8".to_string()],
        )));
        assert_eq!(index.ip_prefix_revision(), unchanged_revision);
        assert!(!updates.has_changed().unwrap());

        index.mark_unavailable("not-ready");
        tokio::time::timeout(std::time::Duration::from_secs(1), updates.changed())
            .await
            .expect("availability update should wake subscriber")
            .expect("ruleset index keeps the watch sender alive");
        let unavailable = core_capture::IpSetProvider::prefix_snapshot(&provider, &names).unwrap();
        assert!(matches!(
            unavailable.sets[1].status,
            core_capture::IpSetPrefixStatus::Unavailable
        ));
    }

    #[test]
    fn capture_claims_only_attach_the_static_host_owner() {
        let config = core_config::loader::load_from_str(
            r#"
version: 1
profile: desktop
capture:
  on: true
  method: virtual_nic
  tun:
    interface_name: mesh-arbitration-test
    address: [198.19.0.0/30, "fd00:1234::/126"]
    auto_route: true
groups:
  main:
    choose: manual
nodes: []
"#,
        )
        .expect("valid capture config");
        let capture =
            core_capture::CapturePlan::from_config(&config.capture).expect("capture plan compiles");

        let unowned = core_capture::host_resource_claims(&capture);
        let owned = capture_resource_claims(&capture);

        assert!(!unowned.is_empty());
        assert_eq!(
            owned
                .iter()
                .map(|owned| owned.claim.clone())
                .collect::<Vec<_>>(),
            unowned
        );
        assert!(
            owned
                .iter()
                .all(|claim| claim.owner.as_str() == "wuther.capture")
        );
    }

    #[test]
    fn disabled_capture_reserves_no_mesh_resources() {
        let config = core_config::loader::load_from_str(
            r#"
version: 1
profile: desktop
capture:
  on: false
groups:
  main:
    choose: manual
nodes: []
"#,
        )
        .expect("valid capture config");
        let capture =
            core_capture::CapturePlan::from_config(&config.capture).expect("capture plan compiles");

        assert!(capture_resource_claims(&capture).is_empty());
    }

    #[tokio::test]
    async fn mesh_fail_stop_observes_an_already_failed_snapshot() {
        let (sender, mut updates) = tokio::sync::watch::channel(core_mesh::MeshSnapshot::new(
            7,
            core_mesh::MeshSupervisorPhase::Failed,
            false,
        ));

        let snapshot = wait_for_mesh_fail_stop(&mut updates)
            .await
            .expect("failed snapshot");
        assert_eq!(snapshot.generation, 7);
        assert!(!snapshot.running);
        drop(sender);
    }

    #[tokio::test]
    async fn mesh_fail_stop_treats_a_closed_status_channel_as_fatal() {
        let (sender, mut updates) = tokio::sync::watch::channel(core_mesh::MeshSnapshot::new(
            1,
            core_mesh::MeshSupervisorPhase::Running,
            true,
        ));
        drop(sender);

        assert!(wait_for_mesh_fail_stop(&mut updates).await.is_none());
    }

    #[cfg(feature = "with_xhttp")]
    #[tokio::test]
    async fn configured_xhttp_is_prebound_by_main_startup_path() {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let plan = core_config::loader::load_from_str(&format!(
            r#"
version: 1
profile: server
listen:
  panel: false
  xhttp:
    enabled: true
    address: 127.0.0.1
    port: {listen_port}
    cleartext: true
    alpn: [h1, h2]
    target: {{host: 127.0.0.1, port: {target_port}}}
    tag: main-xhttp
    settings:
      host: localhost
      path: /main-startup
      mode: stream-one
route:
  preset: direct
"#
        ))
        .unwrap();
        let runtime = Arc::new(Runtime::build(plan.clone()).unwrap());

        let mut handles = start_configured_xhttp_inbounds(&plan, Arc::clone(&runtime))
            .await
            .expect("main startup path must start configured XHTTP");
        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].tag(), "main-xhttp");
        assert_eq!(handles[0].local_addr().port(), listen_port);
        assert!(
            tokio::net::TcpListener::bind(("127.0.0.1", listen_port))
                .await
                .is_err(),
            "main startup helper returned before pre-binding the XHTTP port"
        );

        handles[0].shutdown().await.unwrap();
        runtime.shutdown().await;
        drop(target);
    }
}

fn cmd_check(config: PathBuf) -> anyhow::Result<()> {
    let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
    validate_compiled_components(&plan)?;
    listener_resource_claims(&plan).context("listener resource validation failed")?;
    println!(
        "OK: {} 节点 / {} 分组 / {} 条规则",
        plan.nodes.len(),
        plan.groups.len(),
        plan.route.steps.len()
    );
    Ok(())
}

fn cmd_explain(config: PathBuf) -> anyhow::Result<()> {
    let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
    validate_compiled_components(&plan)?;
    println!("{}", serde_json::to_string_pretty(&plan)?);
    Ok(())
}

fn cmd_migrate(kind: String, input: PathBuf, output: PathBuf) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(&input).context("read input")?;
    let friendly = match kind.as_str() {
        "mihomo" | "clash" => {
            core_config::migrate::migrate_mihomo(&text).map_err(|e| anyhow::anyhow!("{e}"))?
        }
        other => anyhow::bail!("尚不支持的迁移源: {other}（目前支持 mihomo）"),
    };
    std::fs::write(&output, friendly).context("write output")?;
    println!("已写入 {}", output.display());
    Ok(())
}

fn tracing_config_from_user_log(log: &core_config::model::Log) -> core_observe::TracingConfig {
    let file = log.file.on.then(|| core_observe::TracingFileConfig {
        enabled: true,
        path: PathBuf::from(&log.file.path),
    });
    let format = match log.format {
        core_config::model::LogFormat::Json => core_observe::TracingFormat::Json,
        core_config::model::LogFormat::Text => core_observe::TracingFormat::Text,
    };
    core_observe::TracingConfig {
        enabled: log.on && !matches!(log.level, core_config::model::LogLevel::Off),
        level: log.level.as_filter().into(),
        filter: log.filter.clone(),
        stdout: log.stdout,
        file,
        format,
    }
}

/// Attach the process-level host owner to capture's platform-specific claims.
#[cfg(feature = "with_tun")]
fn capture_resource_claims(plan: &core_capture::CapturePlan) -> Vec<core_mesh::HostResourceClaim> {
    use core_mesh::{HostResourceClaim, HostSubsystemId};
    let owner =
        HostSubsystemId::new("wuther.capture").expect("static capture subsystem id is valid");
    core_capture::host_resource_claims(plan)
        .into_iter()
        .map(|claim| HostResourceClaim::new(owner.clone(), claim))
        .collect()
}

async fn cmd_run(config: PathBuf) -> anyhow::Result<()> {
    let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
    validate_compiled_components(&plan)?;
    if let Some(log) = &plan.log {
        core_observe::init_tracing_with_config(tracing_config_from_user_log(log), None);
    } else {
        core_observe::init_tracing();
    }

    // ---------- 进程级 watchdog 安装 ----------
    //
    // 关键：watchdog 走独立 std::thread + 同步文件 IO，与 tokio runtime / tracing
    // 桥接完全解耦。即便整个 tokio 运行时卡死（曾发生：DashMap entry × len 同
    // shard 递归 RwLock；WsHub Arc 循环让 producer 永不退出导致 runtime drop
    // 挂起），运维仍能从 panic.log / watchdog.log 拿到 STUCK / DEADLOCK 报告。
    let log_dir = plan
        .log
        .as_ref()
        .and_then(|l| {
            PathBuf::from(&l.file.path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(|p| p.to_path_buf())
        })
        .unwrap_or_else(|| PathBuf::from("data/logs"));
    let wd = core_observe::Watchdog::install(core_observe::WatchdogConfig {
        panic_log_path: log_dir.join("panic.log"),
        watchdog_log_path: log_dir.join("watchdog.log"),
        ..Default::default()
    });
    // tokio 心跳任务 —— 1Hz 调 wd.heartbeat()。卡死时 watchdog 监督线程
    // 立即捕获并 dump 栈，运维不会再面对"进程在跑但啥都不响应"的黑盒。
    {
        let wd = wd.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                wd.heartbeat();
            }
        });
    }

    info!(name = %plan.name, profile = ?plan.profile, "config loaded");

    // 启动钩子：检测特权 + Android 优先尝试 su 提权再降级。
    let priv_report = ensure_best_effort_privilege().await;
    if !priv_report.is_elevated() {
        warn!(
            target: "privilege",
            "running unprivileged: low ports / TUN / route changes will be limited"
        );
    }

    // 诊断 capture / mesh
    #[cfg(feature = "with_tun")]
    match core_capture::diagnose(&plan.capture, &plan.mesh) {
        Ok(report) => info!(target: "capture", report = ?report, "diagnose"),
        Err(e) => warn!(target: "capture", error = %e, "diagnose failed"),
    }
    info!(target: "mesh", "{}", core_mesh::diagnose(&plan.mesh));

    // 组网监督器必须在 runtime/capture/监听器之前启动。当前公共层注册 capture
    // 对宿主路由、接口和防火墙的保留，以及 DNS、Mixed、API 的固定监听端口；
    // 后续具体产品后端按独立 PR 加入 registry。即使 registry 为空，保留资源也会
    // 出现在 /v1/mesh/status，且同一条事务路径已经覆盖未来后端的
    // probe -> preflight -> reconcile。
    #[cfg(feature = "with_tun")]
    let capture_plan = {
        let mut capture_plan = core_capture::CapturePlan::from_config(&plan.capture)
            .map_err(|error| anyhow::anyhow!("capture resource declaration failed: {error}"))?;
        capture_plan.ipv6_enabled = plan.resolver.ipv6;
        capture_plan
    };
    #[cfg(feature = "with_tun")]
    let mut host_claims = capture_resource_claims(&capture_plan);
    #[cfg(not(feature = "with_tun"))]
    let mut host_claims = Vec::new();
    host_claims.extend(listener_resource_claims(&plan)?);
    let mesh_supervisor = Arc::new(core_mesh::MeshSupervisor::new(
        core_mesh::BackendRegistry::new(),
        host_claims,
    ));
    let mesh_snapshot = mesh_supervisor
        .start()
        .await
        .map_err(|error| anyhow::anyhow!("mesh preflight failed: {error}"))?;
    info!(
        target: "mesh",
        generation = mesh_snapshot.generation,
        reservations = mesh_snapshot.reservations.len(),
        backends = mesh_snapshot.statuses.len(),
        "mesh supervisor ready"
    );

    // 按配置打开持久化 Turso store。
    let store = if plan.database.enabled {
        let store = Store::open_with_options(store_options_from_config(&plan.database))
            .await
            .with_context(|| format!("无法打开 Turso 数据库 {}", plan.database.path.display()))?;
        info!(target: "store", path = %store.path().display(), "store opened");
        Some(store)
    } else {
        info!(target: "store", "persistent store disabled by configuration");
        None
    };

    // 先建好共享的 RulesetIndex —— 让 RouteEngine（runtime 内）与 capture
    // supervisor 共用同一份索引；下方的 RulesetManager 会往里灌编译好的
    // RulesetMatcher。
    let ruleset_index = core_ruleset::RulesetIndex::new();

    let runtime = Arc::new(
        Runtime::build_with(plan.clone(), store, Some(ruleset_index.clone()))
            .await
            .context("运行时出站配置构建失败")?,
    );
    // 把运行期 LogBus 挂到 tracing 桥上 —— 让 /v1/logs 与 Clash 兼容 /logs WS
    // 流式输出。tracing 可能已被早期初始化占用，所以 observe 层使用可后挂载的
    // bus sink，而不是依赖第二次 try_init。
    core_observe::attach_log_bus(runtime.logs.clone());
    info!(target: "observe", "runtime log bus attached");

    // RulesetManager —— 把配置 route.sets 翻成 core-ruleset 的 RulesetSpec
    // 并启动后台轮询拉取。这一步必须在 runtime / capture 之间，确保启动 INFO
    // 日志能看到全部规则集。之前缺少这步会导致 set:geoip-cn 等规则永远不命中。
    let _ruleset_mgr_handle = {
        let specs = build_ruleset_specs(&plan.route.sets);
        let count = specs.len();
        let cache_dir = std::path::PathBuf::from("data/ruleset");
        let mgr = RulesetManager::new(specs, Some(cache_dir.clone()), ruleset_index.clone());
        runtime.set_ruleset_manager(mgr.clone());
        if count == 0 {
            info!(target: "ruleset", "no route.sets configured; manager idle");
        } else {
            let report = mgr.refresh_all().await;
            if !report.failed.is_empty() {
                warn!(
                    target: "ruleset",
                    failed = report.failed.len(),
                    errors = ?report.failed,
                    "ruleset bootstrap completed with unavailable providers"
                );
            }
            mgr.clone().start_periodic();
            info!(
                target: "ruleset",
                count,
                cache_dir = %cache_dir.display(),
                ready = report.updated.len(),
                failed = report.failed.len(),
                "ruleset manager bootstrap completed; periodic refresh started"
            );
        }
        mgr
    };

    // Start traffic-facing sockets only after route providers have reached a
    // terminal initial state, so the first accepted flow cannot bypass a
    // still-pending MRS/RULE-SET.
    #[cfg(feature = "with_xhttp")]
    let mut xhttp_listener_handles =
        start_configured_xhttp_inbounds(&plan, runtime.clone()).await?;
    #[cfg(feature = "with_shadowsocks")]
    let mut shadowsocks_listener_handles =
        start_configured_shadowsocks_inbounds(&plan, runtime.clone()).await?;

    // URLTest：默认每分钟周期探测全部出站（DIRECT/BLOCK 跳过）。
    let urltest = UrlTester::new(UrlTestConfig::default());
    runtime.set_urltest(urltest.clone());
    let _urltest_handle = core_runtime::spawn_periodic(
        urltest.clone(),
        runtime.clone(),
        std::time::Duration::from_secs(60),
    );

    // 连接表周期摘要日志 —— `log.connection-summary-interval > 0s` 时启用。
    // 帮助回答"连接表为什么这么大"：每 N 秒输出 by-process / by-dst / by-rule
    // 聚合 + 长连接清单。0 = 关（默认）。
    let conn_log_interval = runtime
        .plan
        .log
        .as_ref()
        .map(|l| l.connection_summary_interval)
        .unwrap_or_default();
    let _conntable_log_handle = runtime.spawn_conntable_logger(conn_log_interval);

    // 始终创建 FeedManager —— 即便 feeds 为空，dashboard 的 /providers/proxies
    // 仍能拿到一致的（空）provider 列表；start() 在空配置下是 noop，不 spawn 任何 task。
    let feed_mgr_handle = {
        let cache = FeedDiskCache::new("data/feeds").ok();
        let mgr = FeedManager::new(plan.feeds.clone(), cache);
        mgr.set_sink(Arc::new(RuntimeFeedSink {
            runtime: runtime.clone(),
        }));
        let m = mgr.clone();
        let bootstrapped = m.bootstrap_cache().await;
        if bootstrapped > 0 {
            info!(target: "feeds", providers = bootstrapped, "feed cache bootstrapped before capture start");
        }
        m.start();
        if plan.feeds.is_empty() {
            info!(target: "feeds", "no feeds configured; manager idle");
        } else {
            info!(target: "feeds", count = plan.feeds.len(), "feed manager started (auto-fetch on schedule)");
        }
        mgr
    };

    // 启动 capture supervisor（如果配置开启）—— 复用上面建好的 ruleset_index。
    // auto_route / auto_redirect 会改系统路由：启动失败必须 fail-closed，
    // 不能 warn 后继续跑“半透明代理”状态。
    #[cfg(feature = "with_tun")]
    let mut capture_handle: Option<Arc<core_capture::CaptureSupervisor>> = None;
    #[cfg(feature = "with_tun")]
    {
        let capture_fail_closed = plan.capture.on
            && (plan.capture.tun.auto_route
                || plan.capture.tun.auto_redirect
                || matches!(
                    plan.capture.method,
                    core_config::model::CaptureMethod::Tproxy
                        | core_config::model::CaptureMethod::Redirect
                ));
        match core_capture::CaptureSupervisor::build(&plan.capture, &plan.mesh, plan.resolver.ipv6)
        {
            Ok(Some(sup)) => {
                // 注入 IpSetProvider，把 ruleset 的 cidr_v4/cidr_v6 暴露给 supervisor.allow_ip。
                sup.set_ip_set_provider(Arc::new(RulesetIpSetProvider {
                    index: ruleset_index.clone(),
                }));
                if let Err(e) = sup.start(runtime.clone()).await {
                    if capture_fail_closed {
                        // 尽力停掉可能半装好的状态，再把错误抛给 CLI。
                        let _ = sup.stop().await;
                        let _ = mesh_supervisor.stop().await;
                        runtime.shutdown().await;
                        anyhow::bail!(
                            "capture supervisor start failed under auto_route/tproxy/redirect \
                         (fail-closed): {e}"
                        );
                    }
                    warn!(target: "capture", error = %e, "capture supervisor start failed");
                    // start() 已尝试一次事务回滚；若平台 pre_stop/stop 当次失败，
                    // supervisor 会保留 CleanupFailed 账本。调用方必须显式重试，
                    // 否则 drop supervisor 会同时丢失路由/fwmark 的恢复入口。
                    if let Err(cleanup_error) = sup.stop().await {
                        return Err(anyhow::anyhow!(
                            "capture start failed ({e}); cleanup retry also failed \
                         ({cleanup_error}); refusing to continue with possibly active \
                         transparent-capture state"
                        ));
                    }
                } else {
                    capture_handle = Some(sup);
                }
            }
            Ok(None) => {}
            Err(e) => {
                if capture_fail_closed {
                    let _ = mesh_supervisor.stop().await;
                    runtime.shutdown().await;
                    anyhow::bail!(
                        "capture supervisor build failed under auto_route/tproxy/redirect \
                     (fail-closed): {e}"
                    );
                }
                warn!(target: "capture", error = %e, "capture supervisor build failed");
            }
        }
    }

    let mut handles = Vec::new();
    #[cfg(feature = "with_wireguard")]
    let mut wireguard_inbounds: Vec<(
        Arc<WireGuardServer>,
        core_capture::NetstackDispatcherHandles,
    )> = Vec::new();

    #[cfg(feature = "with_wireguard")]
    {
        // WireGuard 服务端入站。WireGuardServer 负责 NoiseIK、cookie/MAC、重放保护、
        // roaming 与多 peer 路由；WireGuardTunIo 把认证后的裸 IP 包接入与系统 TUN
        // 共用的 netstack dispatcher，因此 TCP 与 UDP 最终都经过同一 Runtime 路由。
        for (index, listener) in plan.listen.wireguard.iter().enumerate() {
            let peers = listener
                .peers
                .iter()
                .map(|peer| WireGuardServerPeerConfig {
                    public_key: peer.public_key,
                    preshared_key: peer.preshared_key,
                    allowed_ips: peer.allowed_ips.clone(),
                    reserved: peer.reserved,
                    persistent_keepalive: peer.persistent_keepalive,
                })
                .collect();
            let server = match WireGuardServer::bind(WireGuardServerConfig {
                bind: listener.bind,
                private_key: listener.private_key,
                peers,
                mtu: listener.mtu,
                packet_queue: listener.packet_queue,
                handshake_rate_limit: listener.handshake_rate_limit,
            })
            .await
            .with_context(|| {
                format!(
                    "bind WireGuard inbound listen.wireguard[{index}] at {}",
                    listener.bind
                )
            }) {
                Ok(server) => Arc::new(server),
                Err(error) => {
                    // A later listener can fail after earlier listeners already started their
                    // netstack tasks. Roll every subsystem back explicitly instead of relying
                    // on runtime teardown or detached Tokio task drops.
                    for (server, dispatcher) in wireguard_inbounds.drain(..) {
                        dispatcher.stop();
                        server.close().await;
                    }
                    if let Some(supervisor) = capture_handle.as_ref() {
                        if let Err(cleanup_error) = supervisor.stop().await {
                            warn!(
                                target: "capture",
                                error = %cleanup_error,
                                "capture stop failed while rolling back WireGuard startup"
                            );
                        }
                    }
                    if let Err(cleanup_error) = mesh_supervisor.stop().await {
                        warn!(
                            target: "mesh",
                            error = %cleanup_error,
                            "mesh stop failed while rolling back WireGuard startup"
                        );
                    }
                    feed_mgr_handle.stop();
                    runtime.shutdown().await;
                    return Err(error);
                }
            };
            let mut dispatcher_plan = capture_plan.clone();
            dispatcher_plan.mtu = std::num::NonZeroU16::new(
                u16::try_from(listener.mtu).expect("validated WireGuard MTU always fits into u16"),
            )
            .expect("validated WireGuard MTU is non-zero");
            dispatcher_plan.ipv6_enabled = plan.resolver.ipv6;
            dispatcher_plan.allow_loopback_destination = true;
            let fake_pool = runtime
                .resolver
                .fake_pool()
                .unwrap_or_else(|| Arc::new(core_resolver::FakeIpPool::default()));
            let dispatcher = Arc::new(core_capture::NetstackDispatcher::new(
                dispatcher_plan.clone(),
                Arc::new(core_capture::NatTable::default()),
                Arc::new(core_capture::EimNatTable::new(dispatcher_plan.udp_timeout)),
                fake_pool,
                runtime.dns_service.clone(),
                core_capture::noop_ipset_provider(),
            ));
            let device = Arc::new(core_capture::WireGuardTunIo::new(
                server.clone(),
                format!("wireguard-inbound-{index}"),
                u32::from(dispatcher_plan.mtu.get()),
            ));
            let dispatcher_handles = dispatcher.start(device, runtime.clone());
            info!(
                target: "inbound::wireguard",
                addr = %server.local_addr().unwrap_or(listener.bind),
                peers = listener.peers.len(),
                mtu = listener.mtu,
                "WireGuard inbound ready (TCP+UDP)"
            );
            wireguard_inbounds.push((server, dispatcher_handles));
        }
    }
    #[cfg(feature = "with_young")]
    let mut young_server_handles = Vec::new();

    // Standalone DNS server —— mihomo `dns.listen` 等价。
    // 与 mihomo `dns/server.go::ReCreateServer` 行为一致：空地址 / port=0 → disabled。
    // 把空串过滤前置，是为了避免 spawn_dns_listener 走 disabled 分支后还要在这里
    // 区分"用户没填"和"填了但 mihomo 视作禁用"两种情形——把 `None` 配置直接跳过。
    let mut dns_listener_handle: Option<core_runtime::DnsListener> = None;
    if let Some(listen_addr) = plan
        .resolver
        .listen
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match core_runtime::spawn_dns_listener(listen_addr, runtime.dns_service.clone()).await {
            Ok(h) if h.is_disabled() => {
                info!(
                    target: "dns::listener",
                    listen = %listen_addr,
                    "DNS listener disabled (mihomo: port=0 or empty addr → no bind)"
                );
            }
            Ok(h) => {
                if let (Some(udp), Some(tcp)) = (h.addr(), h.tcp_addr()) {
                    info!(addr = %udp, tcp = %tcp, "DNS server (UDP+TCP) ready");
                }
                dns_listener_handle = Some(h);
            }
            Err(e) => {
                warn!(target: "dns::listener", listen = %listen_addr, error = %e, "DNS listener bind failed");
            }
        }
    }
    // 防止编译器优化掉 handle —— drop 时取消两个后台 task。
    let _dns_listener_keepalive = dns_listener_handle;

    // Young 原生入站：每个监听器由独立 current-thread runtime 驱动 Mozilla Neqo。
    // handle 持有关闭通道，必须存活到全局 shutdown。
    #[cfg(feature = "with_young")]
    for listener in &plan.listen.young {
        let listen = listener
            .socket_addr()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let keys = listener
            .users
            .iter()
            .map(|key| core_young::YoungKey::parse_base64url(key))
            .collect::<std::io::Result<Vec<_>>>()?;
        let server = core_young::YoungServerHandle::start(core_young::YoungServerConfig {
            listen,
            nss_database: PathBuf::from(&listener.nss_database),
            certificate_nickname: listener.certificate_nickname.clone(),
            authority: listener.authority.clone(),
            path: listener.path.clone(),
            keys: core_young::KeyRing::new(keys)?,
            clock_skew: listener.clock_skew,
            idle_timeout: listener.idle_timeout,
            max_streams: listener.max_streams,
            max_sessions: listener.max_sessions,
            max_flows_per_session: listener.max_flows_per_session,
            padding_min: listener.padding_min,
            padding_max: listener.padding_max,
            padding_scheme_length: listener.padding_scheme_length,
            decoy_status: listener.decoy_status,
            decoy_body: listener.decoy_body.as_bytes().to_vec(),
        })?;
        info!(
            addr = %server.local_addr(),
            authority = %listener.authority,
            carrier = "mozilla-neqo-h3-webtransport",
            "Young inbound ready"
        );
        young_server_handles.push(server);
    }

    // Mixed 入站
    if let Some(mixed) = &plan.listen.mixed {
        let addr = mixed.socket_addr().map_err(|e| anyhow::anyhow!("{e}"))?;
        let auth = if plan.listen.auth.is_empty() {
            None
        } else {
            Some(plan.listen.auth.clone())
        };
        let listener = MixedListener {
            tag: mixed.tag.clone(),
            listen: addr,
            auth,
            udp: mixed.udp,
            stream_settings: mixed.stream_settings.clone(),
        };
        let rt = runtime.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_mixed(listener, rt).await {
                warn!(target: "inbound", error = %e, "mixed listener exited");
            }
        }));
        info!(addr = %addr, udp = mixed.udp, "mixed inbound: HTTP+SOCKS5 ready");
    } else {
        info!("listen.local 未配置，跳过 Mixed 入站");
    }

    // Xray gRPC（gun）入站。core-grpc 负责真实 tonic/prost Tun/TunMulti
    // framing，core-inbound 负责 VLESS TCP/UDP/mux 与统一路由运行时。
    #[cfg(feature = "with_grpc")]
    for config in &plan.listen.grpc {
        let listener = GrpcListener::from_config(config)
            .map_err(|error| anyhow::anyhow!("gRPC listener configuration failed: {error}"))?;
        let address = listener.listen_addr();
        let service = listener.server_config().service_name.clone();
        let rt = runtime.clone();
        handles.push(tokio::spawn(async move {
            if let Err(error) = run_grpc(listener, rt).await {
                warn!(target: "inbound::grpc", %address, %error, "gRPC listener exited");
            }
        }));
        info!(addr = %address, %service, "VLESS-over-gRPC inbound ready");
    }

    // 控制面板/API
    #[cfg(feature = "with_api")]
    if plan.ui.on {
        if let Some(panel) = &plan.listen.panel {
            let addr = panel.socket_addr().map_err(|e| anyhow::anyhow!("{e}"))?;
            let server = ApiServer {
                addr,
                runtime: runtime.clone(),
                secret: plan.ui.secret.clone(),
                clash_compat: plan.ui.api.clash_compat,
                urltest: urltest.clone(),
                #[cfg(feature = "with_tun")]
                capture: capture_handle.clone(),
                mesh: Some(mesh_supervisor.clone()),
                feeds: Some(feed_mgr_handle.clone()),
                cors_origins: plan.ui.cors.clone(),
            };
            handles.push(tokio::spawn(async move {
                if let Err(e) = server.run().await {
                    warn!(target: "api", error = %e, "api server exited");
                }
            }));
            info!(addr = %addr, "api server ready (/v1 + clash-compat)");
        }
    }

    info!("WutherCore started, press Ctrl-C to stop.");
    let mut mesh_updates = mesh_supervisor.subscribe();
    let shutdown_signal = tokio::select! {
        signal = wait_for_shutdown_signal() => {
            info!("shutdown signal, bye.");
            signal
        }
        snapshot = wait_for_mesh_fail_stop(&mut mesh_updates) => {
            if let Some(snapshot) = snapshot {
                warn!(
                    target: "mesh",
                    generation = snapshot.generation,
                    phase = ?snapshot.supervisor_phase,
                    conflicts = snapshot.conflicts.len(),
                    "mesh supervision was lost; stopping host capture and runtime fail-closed"
                );
            } else {
                warn!(
                    target: "mesh",
                    "mesh status channel closed; stopping host capture and runtime fail-closed"
                );
            }
            Ok(())
        }
    };
    #[cfg(feature = "with_tun")]
    if let Some(sup) = capture_handle {
        if let Err(e) = sup.stop().await {
            warn!(target: "capture", error = %e, "capture stop failed");
        }
    }
    #[cfg(feature = "with_wireguard")]
    for (server, dispatcher) in wireguard_inbounds {
        dispatcher.stop();
        server.close().await;
    }
    if let Err(error) = mesh_supervisor.stop().await {
        warn!(target: "mesh", error = %error, "mesh supervisor stop failed");
    }
    feed_mgr_handle.stop();
    _ruleset_mgr_handle.stop();
    #[cfg(feature = "with_shadowsocks")]
    for listener in &mut shadowsocks_listener_handles {
        if let Err(error) = listener.shutdown().await {
            warn!(
                target: "inbound::shadowsocks",
                tag = listener.tag(),
                %error,
                "Shadowsocks listener shutdown failed"
            );
        }
    }
    #[cfg(feature = "with_xhttp")]
    for listener in &mut xhttp_listener_handles {
        if let Err(error) = listener.shutdown().await {
            warn!(
                target: "inbound::xhttp",
                tag = listener.tag(),
                %error,
                "XHTTP listener shutdown failed"
            );
        }
    }
    runtime.shutdown().await;
    #[cfg(feature = "with_young")]
    for server in &young_server_handles {
        if let Err(error) = server.shutdown() {
            warn!(target: "young", %error, "Young server shutdown failed");
        }
    }
    for h in handles {
        h.abort();
    }
    shutdown_signal?;
    Ok(())
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

async fn wait_for_mesh_fail_stop(
    updates: &mut tokio::sync::watch::Receiver<core_mesh::MeshSnapshot>,
) -> Option<core_mesh::MeshSnapshot> {
    loop {
        let snapshot = updates.borrow_and_update().clone();
        if !snapshot.running {
            return Some(snapshot);
        }
        if updates.changed().await.is_err() {
            return None;
        }
    }
}

#[cfg(feature = "with_xhttp")]
async fn start_configured_xhttp_inbounds(
    plan: &core_config::runtime_plan::RuntimePlan,
    runtime: Arc<Runtime>,
) -> anyhow::Result<Vec<XhttpListenerHandle>> {
    start_xhttp_listeners(&plan.listen.xhttp, runtime)
        .await
        .context("XHTTP 入站启动失败")
}

#[cfg(feature = "with_shadowsocks")]
async fn start_configured_shadowsocks_inbounds(
    plan: &core_config::runtime_plan::RuntimePlan,
    runtime: Arc<Runtime>,
) -> anyhow::Result<Vec<ShadowsocksListenerHandle>> {
    start_shadowsocks_listeners(&plan.listen.shadowsocks, runtime)
        .await
        .context("Shadowsocks 入站启动失败")
}

/// 把 [`core_ruleset::RulesetIndex`] 适配为 [`core_capture::IpSetProvider`]。
///
/// `route_address_set: ["geoip-cn"]` → 查 ruleset_index 的 `geoip-cn`，
/// 命中 cidr_v4 / cidr_v6 即视为白/黑名单元素。
#[derive(Debug)]
#[cfg(feature = "with_tun")]
struct RulesetIpSetProvider {
    index: Arc<core_ruleset::RulesetIndex>,
}

#[cfg(feature = "with_tun")]
impl core_capture::IpSetProvider for RulesetIpSetProvider {
    fn contains(&self, name: &str, ip: std::net::IpAddr) -> bool {
        let Some(matcher) = self.index.get(name) else {
            return false;
        };
        matcher.matches("", Some(ip), None, None)
    }
    fn names(&self) -> Vec<String> {
        self.index.names()
    }

    fn prefix_snapshot(
        &self,
        names: &[String],
    ) -> Result<core_capture::IpSetPrefixSnapshot, core_capture::IpSetSnapshotError> {
        Ok(map_ruleset_prefix_snapshot(
            self.index.ip_prefix_snapshot(names),
        ))
    }

    fn subscribe_prefix_updates(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
        Some(self.index.subscribe_ip_prefix_updates())
    }

    fn prefix_snapshot_and_subscribe(
        &self,
        names: &[String],
    ) -> Result<
        (
            core_capture::IpSetPrefixSnapshot,
            tokio::sync::watch::Receiver<u64>,
        ),
        core_capture::IpSetSnapshotError,
    > {
        let (snapshot, receiver) = self.index.ip_prefix_snapshot_and_subscribe(names);
        Ok((map_ruleset_prefix_snapshot(snapshot), receiver))
    }
}

#[cfg(feature = "with_tun")]
fn map_ruleset_prefix_snapshot(
    snapshot: core_ruleset::RulesetIpPrefixSnapshot,
) -> core_capture::IpSetPrefixSnapshot {
    let sets = snapshot
        .sets
        .iter()
        .map(|set| {
            let status = match &set.status {
                core_ruleset::RulesetIpPrefixStatus::Ready { semantics } => {
                    let semantics = match semantics {
                        core_ruleset::RulesetIpPrefixSemantics::Exact => {
                            core_capture::IpSetPrefixSemantics::Exact
                        }
                        core_ruleset::RulesetIpPrefixSemantics::Extracted => {
                            core_capture::IpSetPrefixSemantics::Extracted
                        }
                        core_ruleset::RulesetIpPrefixSemantics::NotIpSet => {
                            core_capture::IpSetPrefixSemantics::NotIpSet
                        }
                    };
                    core_capture::IpSetPrefixStatus::Ready { semantics }
                }
                core_ruleset::RulesetIpPrefixStatus::Pending => {
                    core_capture::IpSetPrefixStatus::Pending
                }
                core_ruleset::RulesetIpPrefixStatus::Unavailable => {
                    core_capture::IpSetPrefixStatus::Unavailable
                }
                core_ruleset::RulesetIpPrefixStatus::Missing => {
                    core_capture::IpSetPrefixStatus::Missing
                }
                core_ruleset::RulesetIpPrefixStatus::TooManyPrefixes { limit } => {
                    core_capture::IpSetPrefixStatus::TooManyPrefixes { limit: *limit }
                }
                core_ruleset::RulesetIpPrefixStatus::AllocationFailed => {
                    core_capture::IpSetPrefixStatus::AllocationFailed
                }
                core_ruleset::RulesetIpPrefixStatus::InvalidRange { family } => {
                    core_capture::IpSetPrefixStatus::InvalidRange { family }
                }
            };
            core_capture::IpSetPrefixSet {
                name: set.name.clone(),
                status,
                ipv4: set.ipv4.clone(),
                ipv6: set.ipv6.clone(),
            }
        })
        .collect::<Vec<_>>();
    core_capture::IpSetPrefixSnapshot {
        revision: snapshot.revision,
        sets: Arc::new(sets),
    }
}

/// FeedSink 实现：把订阅刷新结果直接交给 Runtime 注册。
struct RuntimeFeedSink {
    runtime: Arc<Runtime>,
}

#[async_trait]
impl FeedSink for RuntimeFeedSink {
    async fn on_update(&self, update: &FeedUpdate) -> Result<(), String> {
        self.runtime
            .apply_feed_nodes(&update.name, update.nodes.clone())
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod traffic_cli_tests {
    use super::*;
    use unicode_width::UnicodeWidthStr;

    fn traffic_row(
        dimension: &str,
        label: &str,
        upload: u64,
        download: u64,
        connections: u64,
    ) -> TrafficRow {
        let upload = BigUint::from(upload);
        let download = BigUint::from(download);
        TrafficRow {
            blob: TrafficTotalBlob {
                dimension: dimension.into(),
                label: label.into(),
                upload: upload.to_str_radix(10),
                download: download.to_str_radix(10),
                connections,
                ..TrafficTotalBlob::default()
            },
            total: &upload + &download,
            upload,
            download,
        }
    }

    fn assert_table_fits(output: &str, width: usize) {
        for line in output.lines() {
            assert!(
                UnicodeWidthStr::width(line) <= width,
                "line exceeds width {width}: {line:?}"
            );
        }
    }

    #[test]
    fn byte_formatter_reaches_bb_and_keeps_growing() {
        let one_bb = BigUint::from(1024u16).pow(9);
        assert_eq!(format_big_bytes(&one_bb), "1 BB");

        let beyond_bb = BigUint::from(1024u16).pow(12);
        assert_eq!(format_big_bytes(&beyond_bb), "1073741824 BB");
    }

    #[test]
    fn byte_formatter_accepts_arbitrary_precision_values() {
        let value = parse_traffic_integer(
            "999999999999999999999999999999999999999999999999999999999999999999",
        )
        .unwrap();
        assert!(format_big_bytes(&value).ends_with(" BB"));
        assert_eq!(
            value.to_str_radix(10),
            "999999999999999999999999999999999999999999999999999999999999999999"
        );
    }

    #[test]
    fn epoch_formatter_is_stable_utc() {
        assert_eq!(format_epoch(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_epoch(1_704_067_200), "2024-01-01 00:00:00 UTC");
    }

    #[test]
    fn traffic_summary_is_a_bounded_unicode_table() {
        let mut total = traffic_row("total", "all", 1_048_576, 2_097_152, 12_345);
        total.blob.first_seen_secs = 1_704_067_200;
        total.blob.last_seen_secs = 1_704_070_800;

        let output = render_traffic_summary_table(
            "D:\\WutherCore\\data\\state\\wuthercore.db",
            &total,
            false,
            Some(72),
        );

        assert!(output.contains("统计项"));
        assert!(output.contains("累计总量"));
        assert!(output.contains("12,345"));
        assert!(output.contains("2024-01-01 00:00:00 UTC"));
        assert_table_fits(&output, 72);
    }

    #[test]
    fn traffic_table_uses_full_columns_on_wide_terminals() {
        let total = traffic_row("total", "all", 10_000_000, 20_000_000, 100);
        let row = traffic_row("outbound", "香港专线 HK-D-1-0.2x", 1_000_000, 2_000_000, 12);
        let output = render_traffic_dimension_table(&[&row], &total, false, Some(120));

        for header in ["名称", "上传", "下载", "总量", "占比", "连接"] {
            assert!(output.contains(header), "missing header {header}");
        }
        assert!(output.contains("香港专线"));
        assert!(!output.contains("明细"));
        assert_table_fits(&output, 120);
    }

    #[test]
    fn traffic_table_keeps_every_metric_on_narrow_terminals() {
        let total = traffic_row("total", "all", 10_000_000, 20_000_000, 100);
        let row = traffic_row("outbound", "香港专线 HK-D-1-0.2x", 1_000_000, 2_000_000, 12);
        let output = render_traffic_dimension_table(&[&row], &total, false, Some(52));

        assert!(output.contains("明细"));
        for metric in ["上传", "下载", "总量", "占比", "连接"] {
            assert!(output.contains(metric), "missing metric {metric}");
        }
        assert_table_fits(&output, 52);
    }

    #[test]
    fn database_config_maps_to_turso_options_without_loss() {
        let plan = core_config::loader::load_from_str(
            r#"
version: 1
database:
  path: state/custom.db
  busy-timeout: 11s
  max-write-attempts: 31
  multiprocess-wal: on
  experimental-vacuum: false
"#,
        )
        .unwrap();

        let options = store_options_from_config(&plan.database);
        assert_eq!(options.path, PathBuf::from("state/custom.db"));
        assert_eq!(options.busy_timeout, std::time::Duration::from_secs(11));
        assert_eq!(options.max_write_attempts, 31);
        assert_eq!(options.multiprocess_wal, MultiprocessWal::Enabled);
        assert!(!options.experimental_vacuum);
    }
}
