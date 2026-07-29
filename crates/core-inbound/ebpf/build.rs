use which::which;

fn main() {
    let linker = which("bpf-linker")
        .expect("bpf-linker is required for with_ebpf; install it with `cargo install bpf-linker`");
    println!("cargo:rerun-if-changed={}", linker.display());
}
