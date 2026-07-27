use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=aidl");

    // These bindings are target-only. Keeping the build script a no-op for
    // desktop targets avoids producing unused generated files.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("android") {
        return;
    }

    for (source, output) in [
        (
            "aidl/api29/android/content/pm/IPackageManager.aidl",
            "package_manager_api29.rs",
        ),
        (
            "aidl/api30/android/content/pm/IPackageManager.aidl",
            "package_manager_api30.rs",
        ),
        (
            "aidl/api31/android/content/pm/IPackageManager.aidl",
            "package_manager_api31.rs",
        ),
    ] {
        rsbinder_aidl::Builder::new()
            .set_async_support(false)
            .source(PathBuf::from(source))
            .output(PathBuf::from(output))
            .generate()
            .unwrap_or_else(|error| panic!("failed to generate {source}: {error:?}"));
    }
}
