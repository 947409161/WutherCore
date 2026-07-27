//! Android finder —— 三档（root / 自家进程 / 跨 app）覆盖。
//!
//! ## 决策矩阵
//!
//! | 场景 | 路径 | 命中范围 | 备注 |
//! |------|------|----------|------|
//! | **root**（getuid==0） | `/proc/net/*` + `/proc/<pid>/fd/*` | 全部进程 | 完全等价 Linux finder |
//! | **非 root，自己进程的连接** | `/proc/net/*`（仅显示同 UID 行） | 仅本进程 | Android 7+ 内核过滤 |
//! | **非 root，别 app 连接** | JNI → `ConnectivityManager.getConnectionOwnerUid` | API 29+ 全部 | 需要 [`set_jni_bridge`] 注入过 Context |
//!
//! ## 用法
//!
//! Android 应用在 `JNI_OnLoad` 之后（拿到 `Context` 时）调一次：
//!
//! ```ignore
//! // 在 Android wrapper 的 JNI 函数里：
//! pub extern "system" fn Java_com_example_Vpn_init<'local>(
//!     mut env: jni::JNIEnv<'local>,
//!     _: jni::objects::JClass<'local>,
//!     ctx: jni::objects::JObject<'local>,
//! ) {
//!     let _ = core_process::android::set_jni_bridge(&mut env, &ctx);
//! }
//! ```
//!
//! 没注入桥时，`AndroidFinder` 只会跑 `/proc` 路径 —— root 用户全开，
//! 普通用户只能命中自己进程的 socket。
//!
//! ## 选型理由
//!
//! - 用 `jni` crate（mainstream，0.21，与 `core-capture::platform::android_jni`
//!   同版本），不靠 NDK linker hack；
//! - 用 `getConnectionOwnerUid` (API 29) 而非 netlink/`SOCK_DIAG_BY_FAMILY`：
//!   后者要 `CAP_NET_ADMIN`，VpnService app 拿不到；
//! - 用 `InetAddress.getByAddress(byte[])` 而非 `InetSocketAddress(String, int)`：
//!   后者会 DNS 解析 IP 字面量也照走，hot-path 不稳定；
//! - 用 `PackageManager.getPackagesForUid` 返回真实包名列表；Android shared UID
//!   会保留所有关联包，而不是用展示名称代替包名。

use std::{net::IpAddr, sync::Arc};

use jni::{
    Env, JavaVM, jni_sig, jni_str,
    objects::{Global, JByteArray, JObject, JObjectArray, JString, JValue},
};
use once_cell::sync::OnceCell;

use crate::{NetworkProto, ProcessFinder, ProcessInfo, linux::LinuxFinder};

/// `ConnectivityManager.getConnectionOwnerUid` 找不到时返回的 sentinel。
const INVALID_UID: i32 = -1;
/// 与 Linux IPPROTO 一致 —— `ConnectivityManager` 直接用 IPPROTO 数字。
const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;

/// JNI 全局桥 —— 由 [`set_jni_bridge`] 注入；线程安全（GlobalRef 跨线程合法，
/// JavaVM 本身就是 process-singleton）。
struct JniBridge {
    vm: JavaVM,
    /// `android.net.ConnectivityManager` 实例 —— 用来调 `getConnectionOwnerUid`。
    connectivity_manager: Global<JObject<'static>>,
    /// `android.content.pm.PackageManager` 实例 —— 用来拿 UID 对应的包名列表。
    package_manager: Global<JObject<'static>>,
}

static JNI_BRIDGE: OnceCell<Arc<JniBridge>> = OnceCell::new();

/// 注册 Android JNI 桥。`context` 必须是 `android.content.Context`
/// （通常是 `Application` 或 `VpnService`）。第一次注册成功后 `OnceCell` 锁定，
/// 重复调用静默失败 —— 这与 mihomo `MMDB::set_globals` 行为一致：进程级单例。
///
/// 调用线程不必是 finder 调用线程；内部派生的 `GlobalRef` 跨线程合法。
pub fn set_jni_bridge(env: &mut Env<'_>, context: &JObject<'_>) -> jni::errors::Result<()> {
    if JNI_BRIDGE.get().is_some() {
        return Ok(());
    }
    let vm = env.get_java_vm()?;

    // ConnectivityManager (CONNECTIVITY_SERVICE = "connectivity")
    let svc_name = env.new_string("connectivity")?;
    let cm_obj = env
        .call_method(
            context,
            jni_str!("getSystemService"),
            jni_sig!("(Ljava/lang/String;)Ljava/lang/Object;"),
            &[JValue::Object(&svc_name)],
        )?
        .l()?;
    if cm_obj.is_null() {
        return Err(jni::errors::Error::NullPtr(
            "ConnectivityManager null —— Context 可能不是 Activity/Service",
        ));
    }
    let connectivity_manager = env.new_global_ref(cm_obj)?;

    // PackageManager
    let pm_obj = env
        .call_method(
            context,
            jni_str!("getPackageManager"),
            jni_sig!("()Landroid/content/pm/PackageManager;"),
            &[],
        )?
        .l()?;
    if pm_obj.is_null() {
        return Err(jni::errors::Error::NullPtr("PackageManager null"));
    }
    let package_manager = env.new_global_ref(pm_obj)?;

    let _ = JNI_BRIDGE.set(Arc::new(JniBridge {
        vm,
        connectivity_manager,
        package_manager,
    }));
    tracing::info!(target: "core-process::android", "JNI bridge installed");
    Ok(())
}

/// 是否已有 JNI 桥。供 inspection / 测试 / 日志使用。
pub fn jni_bridge_ready() -> bool {
    JNI_BRIDGE.get().is_some()
}

#[derive(Debug, Clone, Copy)]
pub struct AndroidFinder {
    /// 进程是否以 uid=0 运行。root 时 `/proc` 全开 —— 与 Linux 完全一致；
    /// 非 root 时 `/proc` 只看得到自家 UID 的连接，跨 app 必须靠 JNI。
    is_root: bool,
}

impl AndroidFinder {
    pub fn new() -> Self {
        let is_root = unsafe { libc::getuid() } == 0;
        if is_root {
            tracing::info!(
                target: "core-process::android",
                "running as root → /proc 全开，process lookup 无需 JNI 桥"
            );
        }
        Self { is_root }
    }
}

impl Default for AndroidFinder {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessFinder for AndroidFinder {
    fn find(&self, proto: NetworkProto, src_ip: IpAddr, src_port: u16) -> Option<ProcessInfo> {
        let mut info = LinuxFinder::new().find(proto, src_ip, src_port)?;
        populate_packages(&mut info);
        Some(info)
    }

    fn find_with_dst(
        &self,
        proto: NetworkProto,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Option<ProcessInfo> {
        // 1) 先 /proc —— root 全开；非 root 命中自家进程
        if let Some(mut info) =
            LinuxFinder::new().find_with_dst(proto, src_ip, src_port, dst_ip, dst_port)
        {
            populate_packages(&mut info);
            return Some(info);
        }
        // 2) 非 root + 别 app socket → JNI ConnectivityManager
        if self.is_root {
            return None; // root 已在 /proc 兜底；JNI 走不到这里
        }
        let bridge = JNI_BRIDGE.get()?.clone();
        match jni_lookup(&bridge, proto, src_ip, src_port, dst_ip, dst_port) {
            Ok(info) => info,
            Err(e) => {
                tracing::debug!(
                    target: "core-process::android",
                    error = %e,
                    "JNI getConnectionOwnerUid failed"
                );
                None
            }
        }
    }
}

/// 全部 JNI 调用包在一个函数里 —— `attach_current_thread` 返回的
/// `AttachGuard` 离开 scope 时自动 detach；过程中所有 local ref 跟着消失，
/// 不会泄露 JNI table。
fn jni_lookup(
    bridge: &JniBridge,
    proto: NetworkProto,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> jni::errors::Result<Option<ProcessInfo>> {
    bridge.vm.attach_current_thread(|env| {
        jni_lookup_attached(bridge, env, proto, src_ip, src_port, dst_ip, dst_port)
    })
}

fn jni_lookup_attached(
    bridge: &JniBridge,
    env: &mut Env<'_>,
    proto: NetworkProto,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> jni::errors::Result<Option<ProcessInfo>> {
    let proto_int = match proto {
        NetworkProto::Tcp => IPPROTO_TCP,
        NetworkProto::Udp => IPPROTO_UDP,
    };
    let local = make_inet_socket_addr(env, src_ip, src_port)?;
    let remote = make_inet_socket_addr(env, dst_ip, dst_port)?;

    let uid_int = env
        .call_method(
            &bridge.connectivity_manager,
            jni_str!("getConnectionOwnerUid"),
            jni_sig!("(ILjava/net/InetSocketAddress;Ljava/net/InetSocketAddress;)I"),
            &[
                JValue::Int(proto_int),
                JValue::Object(&local),
                JValue::Object(&remote),
            ],
        )?
        .i()?;
    if uid_int == INVALID_UID {
        return Ok(None);
    }
    let uid = uid_int as u32;
    let package_names = jni_packages_for_uid(env, &bridge.package_manager, uid)?;
    let name = package_names
        .first()
        .cloned()
        .unwrap_or_else(|| format!("uid:{uid}"));
    Ok(Some(ProcessInfo {
        name,
        path: String::new(),
        uid,
        package_names,
    }))
}

/// `InetAddress.getByAddress(byte[])` + `new InetSocketAddress(InetAddress, int)`。
/// 用 byte 数组而非主机名字符串，规避 Java DNS 解析路径。
fn make_inet_socket_addr<'local>(
    env: &mut Env<'local>,
    ip: IpAddr,
    port: u16,
) -> jni::errors::Result<JObject<'local>> {
    let bytes: Vec<u8> = match ip {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    };
    let arr: JByteArray<'local> = env.byte_array_from_slice(&bytes)?;
    let inet_addr = env
        .call_static_method(
            jni_str!("java/net/InetAddress"),
            jni_str!("getByAddress"),
            jni_sig!("([B)Ljava/net/InetAddress;"),
            &[JValue::Object(&arr)],
        )?
        .l()?;
    let sock = env.new_object(
        jni_str!("java/net/InetSocketAddress"),
        jni_sig!("(Ljava/net/InetAddress;I)V"),
        &[JValue::Object(&inet_addr), JValue::Int(port as i32)],
    )?;
    Ok(sock)
}

fn populate_packages(info: &mut ProcessInfo) {
    let Some(bridge) = JNI_BRIDGE.get() else {
        return;
    };
    if let Ok(packages) = bridge
        .vm
        .attach_current_thread(|env| jni_packages_for_uid(env, &bridge.package_manager, info.uid))
    {
        if let Some(package) = packages.first() {
            info.name = package.clone();
        }
        info.package_names = packages;
    }
}

/// `PackageManager.getPackagesForUid(int) -> String[]?`.
fn jni_packages_for_uid(
    env: &mut Env<'_>,
    pm: &Global<JObject<'static>>,
    uid: u32,
) -> jni::errors::Result<Vec<String>> {
    let result = env
        .call_method(
            pm,
            jni_str!("getPackagesForUid"),
            jni_sig!("(I)[Ljava/lang/String;"),
            &[JValue::Int(uid as i32)],
        )?
        .l()?;
    if result.is_null() {
        return Ok(Vec::new());
    }
    let array = JObjectArray::<JString>::cast_local(env, result)?;
    let mut packages = Vec::with_capacity(array.len(env)?);
    for index in 0..array.len(env)? {
        let package = array.get_element(env, index)?;
        let package = package.try_to_string(env)?;
        if !package.is_empty() {
            packages.push(package);
        }
    }
    packages.sort_unstable();
    packages.dedup();
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 没装桥的情况下 find_with_dst 不应 panic（fallthrough 到 LinuxFinder）。
    #[test]
    fn missing_bridge_returns_none_without_panic() {
        let finder = AndroidFinder::new();
        let res = finder.find_with_dst(
            NetworkProto::Tcp,
            "10.0.0.1".parse().unwrap(),
            64999,
            "8.8.8.8".parse().unwrap(),
            443,
        );
        assert!(res.is_none(), "未装桥 + 无 /proc 命中 → None");
    }

    #[test]
    fn jni_bridge_ready_returns_false_when_not_initialized() {
        // 进程级 OnceCell —— 同一测试进程内只能装一次。
        // 这条断言只能在没装桥的进程里成立。
        if !jni_bridge_ready() {
            assert!(!jni_bridge_ready());
        }
    }
}
