//! Renders the ABI header into `$OUT_DIR`, then compiles
//! `bpf/fsblame.bpf.c` and `bpf/probe.bpf.c` with clang (BPF target, CO-RE). Needs only
//! clang; no nightly Rust, no bpf-linker.

use std::{env, fs, path::PathBuf, process::Command};

const OBJECTS: [&str; 2] = ["fsblame", "probe"];

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));

    let header = fsblame_abi::header();
    fs::write(out.join("fsblame_wire.h"), header.finish()).expect("write fsblame_wire.h");
    fs::write(
        out.join("abi_hash.rs"),
        format!(
            "/// ABI hash of `fsblame_wire.h` (`FSBLAME_WIRE_H_ABI_HASH`).\npub const ABI_HASH: u64 = {:#018x};\n",
            header.abi_hash()
        ),
    )
    .expect("write abi_hash.rs");

    // libbpf's bpf_tracing.h keys pt_regs access off __TARGET_ARCH_<arch>.
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").expect("target arch").as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        "riscv64" => "riscv",
        "s390x" => "s390",
        "loongarch64" => "loongarch",
        "powerpc64" => "powerpc",
        other => panic!("no __TARGET_ARCH mapping for {other}"),
    };
    let target = match env::var("CARGO_CFG_TARGET_ENDIAN").expect("target endian").as_str() {
        "big" => "bpfeb",
        _ => "bpfel",
    };
    let clang = env::var_os("CLANG").unwrap_or_else(|| "clang".into());
    for name in OBJECTS {
        let status = Command::new(&clang)
            .args(["-target", target, "-O2", "-g", "-mcpu=v3", "-Wall", "-Werror"])
            .arg(format!("-D__TARGET_ARCH_{arch}"))
            .args(["-I", "bpf", "-I", "bpf/include", "-I"])
            .arg(&out)
            .arg("-c")
            .arg(format!("bpf/{name}.bpf.c"))
            .arg("-o")
            .arg(out.join(format!("{name}.bpf.o")))
            .status()
            .unwrap_or_else(|e| panic!("failed to run {}: {e}", clang.display()));
        assert!(status.success(), "clang failed on bpf/{name}.bpf.c: {status}");
    }
    println!("cargo:rerun-if-changed=bpf");
    println!("cargo:rerun-if-env-changed=CLANG");
}
