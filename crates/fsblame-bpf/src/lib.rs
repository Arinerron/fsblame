//! fsblame's BPF objects, built from `bpf/*.bpf.c` by `build.rs`.
//!
//! The objects are CO-RE ELF files; load them with aya against the running kernel's BTF.

#![no_std]

include!(concat!(env!("OUT_DIR"), "/abi_hash.rs"));

/// 8-byte aligned storage, as the ELF parser requires.
#[repr(C, align(8))]
struct Aligned<B: ?Sized>(B);

macro_rules! object {
    ($name:literal) => {{
        static OBJECT: &Aligned<[u8]> =
            &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/", $name, ".bpf.o")));
        &OBJECT.0
    }};
}

/// The tracer: file-operation fentry programs, sched tracepoints and their maps.
pub static OBJECT: &[u8] = object!("fsblame");

/// Feature probes for `fsblame doctor`: a do-nothing program per attach point, named
/// `probe_<function>` (fentry) or `probe_<tracepoint>` (tp_btf), and no output.
pub static PROBE_OBJECT: &[u8] = object!("probe");
