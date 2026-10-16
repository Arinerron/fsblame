//! The running kernel's BTF, read once: aya's parse, to load programs against, and the facts
//! aya does not expose (function prototypes).
//!
//! Raw BTF (`include/uapi/linux/btf.h`) is a header, then type records numbered from 1, each a
//! `{name_off, info, size_or_type}` triple followed by kind-specific data, then a string table.
//! The kernel publishes it in host byte order.

use std::{fmt, fs, path::PathBuf, sync::OnceLock};

use aya::{Btf, BtfError, EbpfLoader, Endianness};

/// The running kernel's BTF.
const VMLINUX: &str = "/sys/kernel/btf/vmlinux";

const MAGIC: u16 = 0xeb9f;
const KIND_FUNC: u32 = 12;
const KIND_FUNC_PROTO: u32 = 13;

/// What loading the tracer needs from the running kernel's BTF.
pub struct KernelBtf {
    /// aya's parse, for CO-RE relocations and attach targets: 16 MiB on Linux 7.2, so it is
    /// dropped once the programs are attached.
    pub btf: Btf,
    /// Parameters of `security_inode_setattr`; `None` when it is not there.
    pub setattr_params: Option<usize>,
}

impl KernelBtf {
    /// Reads `/sys/kernel/btf/vmlinux` once, for both.
    pub fn read() -> Result<Self, BtfError> {
        let raw = fs::read(VMLINUX).map_err(|error| BtfError::FileError {
            path: PathBuf::from(VMLINUX),
            error,
        })?;
        Ok(Self {
            setattr_params: func_params(&raw, "security_inode_setattr"),
            btf: Btf::parse(&raw, Endianness::default())?,
        })
    }
}

impl fmt::Debug for KernelBtf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelBtf")
            .field("setattr_params", &self.setattr_params)
            .finish_non_exhaustive()
    }
}

/// A program loader set up with the kernel BTF in `cache`, read into it unless there, and
/// that BTF, to attach the programs against. [`EbpfLoader::new`] parses the kernel BTF for
/// itself; that copy is dropped before `cache` is filled, so a load holds one parse at a time.
pub fn loader(cache: &OnceLock<KernelBtf>) -> Result<(EbpfLoader<'_>, &KernelBtf), BtfError> {
    let mut loader = EbpfLoader::new();
    loader.btf(None);
    let kernel = if let Some(kernel) = cache.get() {
        kernel
    } else {
        let kernel = KernelBtf::read()?;
        cache.get_or_init(|| kernel)
    };
    loader.btf(Some(&kernel.btf));
    Ok((loader, kernel))
}

/// Parameters of function `name` in raw BTF; `None` when it is not there or the BTF does not
/// parse.
pub fn func_params(btf: &[u8], name: &str) -> Option<usize> {
    let raw = Raw::parse(btf)?;
    let func = raw
        .types()
        .find(|t| t.kind() == KIND_FUNC && raw.name(t.name_off) == Some(name.as_bytes()))?;
    let proto = raw.types().nth(index(func.size_or_type).checked_sub(1)?)?;
    (proto.kind() == KIND_FUNC_PROTO).then_some(proto.vlen())
}

fn index(v: u32) -> usize {
    usize::try_from(v).expect("usize holds u32")
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// The type and string sections of raw BTF.
struct Raw<'a> {
    types: &'a [u8],
    strings: &'a [u8],
}

/// The common part of one type record.
#[derive(Clone, Copy)]
struct TypeHdr {
    name_off: u32,
    info: u32,
    size_or_type: u32,
}

impl TypeHdr {
    fn kind(self) -> u32 {
        (self.info >> 24) & 0x1f
    }

    fn vlen(self) -> usize {
        index(self.info & 0xffff)
    }

    /// Bytes of kind-specific data after the header; `None` for a kind this parser does not
    /// know, whose size it cannot skip.
    fn extra(self) -> Option<usize> {
        let vlen = self.vlen();
        Some(match self.kind() {
            // PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT, TYPE_TAG.
            2 | 7..=12 | 16 | 18 => 0,
            // INT, VAR, DECL_TAG.
            1 | 14 | 17 => 4,
            // ARRAY.
            3 => 12,
            // ENUM, FUNC_PROTO: {name, value} and {name, type} pairs.
            6 | 13 => 8 * vlen,
            // STRUCT, UNION, DATASEC, ENUM64.
            4 | 5 | 15 | 19 => 12 * vlen,
            _ => return None,
        })
    }
}

impl<'a> Raw<'a> {
    fn parse(btf: &'a [u8]) -> Option<Self> {
        if btf.get(..2)? != MAGIC.to_ne_bytes() {
            return None;
        }
        let field = |at| u32_at(btf, at).map(index);
        let hdr_len = field(4)?;
        let section = |off: usize, len: usize| {
            let start = hdr_len.checked_add(off)?;
            btf.get(start..start.checked_add(len)?)
        };
        Some(Self {
            types: section(field(8)?, field(12)?)?,
            strings: section(field(16)?, field(20)?)?,
        })
    }

    /// The type records in id order, from id 1; ends early at a record that does not parse.
    fn types(&self) -> impl Iterator<Item = TypeHdr> + '_ {
        let mut at = 0;
        std::iter::from_fn(move || {
            let t = TypeHdr {
                name_off: u32_at(self.types, at)?,
                info: u32_at(self.types, at + 4)?,
                size_or_type: u32_at(self.types, at + 8)?,
            };
            at += 12 + t.extra()?;
            Some(t)
        })
    }

    /// The NUL-terminated string at `off`.
    fn name(&self, off: u32) -> Option<&'a [u8]> {
        let rest = self.strings.get(index(off)..)?;
        Some(&rest[..rest.iter().position(|&b| b == 0)?])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Raw BTF with `types` (header triple plus extra words) and `strings`.
    fn btf(types: &[&[u32]], strings: &[u8]) -> Vec<u8> {
        let words: Vec<u8> = types
            .iter()
            .flat_map(|t| t.iter().flat_map(|w| w.to_ne_bytes()))
            .collect();
        let len = |n: usize| u32::try_from(n).unwrap();
        let mut out = MAGIC.to_ne_bytes().to_vec();
        out.extend_from_slice(&[1, 0]);
        for w in [
            24,
            0,
            len(words.len()),
            len(words.len()),
            len(strings.len()),
        ] {
            out.extend_from_slice(&u32::to_ne_bytes(w));
        }
        out.extend_from_slice(&words);
        out.extend_from_slice(strings);
        out
    }

    const fn info(kind: u32, vlen: u32) -> u32 {
        (kind << 24) | vlen
    }

    #[test]
    fn counts_the_parameters_of_the_named_function() {
        // Strings: "", "int", "a", "b", "f", "g".
        let strings = b"\0int\0a\0b\0f\0g\0";
        let types: [&[u32]; 6] = [
            // 1: INT int, with its encoding word.
            &[1, info(1, 0), 4, 32],
            // 2: STRUCT a { int b; }: a member skipped by vlen.
            &[5, info(4, 1), 4, 7, 1, 0],
            // 3: FUNC_PROTO (int a, int b).
            &[0, info(13, 2), 1, 5, 1, 7, 1],
            // 4: FUNC_PROTO (int a).
            &[0, info(13, 1), 1, 5, 1],
            // 5: FUNC f -> 3, 6: FUNC g -> 4.
            &[9, info(12, 0), 3],
            &[11, info(12, 0), 4],
        ];
        let raw = btf(&types, strings);
        assert_eq!(func_params(&raw, "f"), Some(2));
        assert_eq!(func_params(&raw, "g"), Some(1));
        // A struct of that name is not a function.
        assert_eq!(func_params(&raw, "a"), None);
        assert_eq!(func_params(&raw, "h"), None);
        // Cut inside the string table.
        assert_eq!(func_params(&raw[..raw.len() - 5], "f"), None);
    }
}
