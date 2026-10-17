//! The running kernel's BTF, read once: aya's parse, to load programs against, and the facts
//! aya does not expose (function prototypes).
//!
//! Raw BTF (`include/uapi/linux/btf.h`) is a header, then type records numbered from 1, each a
//! `{name_off, info, size_or_type}` triple followed by kind-specific data, then a string table.
//! The kernel publishes it in host byte order.

use std::{fmt, fs, path::PathBuf, sync::OnceLock};

use aya::{Btf, BtfError, EbpfLoader, Endianness};

use crate::ops::FS_HOOKS;

/// The running kernel's BTF.
const VMLINUX: &str = "/sys/kernel/btf/vmlinux";

const MAGIC: u16 = 0xeb9f;
const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_STRUCT: u32 = 4;
const KIND_ENUM: u32 = 6;
const KIND_FUNC: u32 = 12;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_ENUM64: u32 = 19;
/// Most modifiers and typedefs looked through to reach a type.
const RESOLVE_MAX: usize = 16;

/// The kernel function whose arity `on_setattr` is loaded for.
pub const SETATTR: &str = "security_inode_setattr";

/// What the tracer reads of a kernel function's prototype.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prototype {
    /// Number of parameters.
    pub params: usize,
    /// Index of the last parameter that is a `struct dentry *`: the dentry an operation acts on
    /// (`vfs_link` has the existing name first, the new one last).
    pub dentry: Option<usize>,
    /// What it returns.
    pub ret: Ret,
}

/// The return type of a function, as far as telling success goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ret {
    /// Nothing.
    Void,
    /// An integer or an enum.
    Int,
    /// A pointer.
    Pointer,
    /// Any other type.
    Other,
}

/// What loading the tracer needs from the running kernel's BTF.
pub struct KernelBtf {
    /// aya's parse, for CO-RE relocations and attach targets: 16 MiB on Linux 7.2, so it is
    /// dropped once the programs are attached.
    pub btf: Btf,
    /// Prototypes of [`SETATTR`] and of the functions of the hooks that have a `.rodata` shape
    /// ([`Hook::shape`](crate::ops::Hook::shape)), those in BTF.
    prototypes: Vec<(&'static str, Prototype)>,
}

impl KernelBtf {
    /// Reads `/sys/kernel/btf/vmlinux` once, for both.
    pub fn read() -> Result<Self, BtfError> {
        let raw = fs::read(VMLINUX).map_err(|error| BtfError::FileError {
            path: PathBuf::from(VMLINUX),
            error,
        })?;
        let names: Vec<&'static str> = std::iter::once(SETATTR)
            .chain(
                FS_HOOKS
                    .iter()
                    .filter(|hook| hook.shape().is_some())
                    .map(|hook| hook.function),
            )
            .collect();
        let found = prototypes(&raw, &names);
        Ok(Self {
            prototypes: names
                .into_iter()
                .zip(found)
                .filter_map(|(name, proto)| Some((name, proto?)))
                .collect(),
            btf: Btf::parse(&raw, Endianness::default())?,
        })
    }

    /// The prototype of `function`, one of those read; `None` when it is not in BTF.
    pub fn prototype(&self, function: &str) -> Option<Prototype> {
        self.prototypes
            .iter()
            .find(|&&(name, _)| name == function)
            .map(|&(_, proto)| proto)
    }
}

impl fmt::Debug for KernelBtf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelBtf")
            .field("prototypes", &self.prototypes)
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

/// The prototypes of the functions `names` in raw BTF, in that order: `None` for one that is
/// not there, or every one when the BTF does not parse. One pass over the types.
pub fn prototypes(btf: &[u8], names: &[&str]) -> Vec<Option<Prototype>> {
    let Some(raw) = Raw::parse(btf) else {
        return vec![None; names.len()];
    };
    // Where each type record starts, by id - 1, to follow type references.
    let mut at = Vec::new();
    let mut funcs = vec![None; names.len()];
    for (off, t) in raw.types() {
        at.push(off);
        if t.kind() == KIND_FUNC
            && let Some(name) = raw.name(t.name_off)
            && let Some(i) = names.iter().position(|n| n.as_bytes() == name)
        {
            funcs[i] = Some(t.size_or_type);
        }
    }
    funcs
        .into_iter()
        .map(|proto| proto.and_then(|id| raw.prototype(&at, id)))
        .collect()
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

    /// The type records in id order, from id 1, each with where it starts; ends early at a
    /// record that does not parse.
    fn types(&self) -> impl Iterator<Item = (usize, TypeHdr)> + '_ {
        let mut at = 0;
        std::iter::from_fn(move || {
            let t = self.hdr(at)?;
            let start = at;
            at += 12 + t.extra()?;
            Some((start, t))
        })
    }

    /// The type record header at `off`.
    fn hdr(&self, off: usize) -> Option<TypeHdr> {
        Some(TypeHdr {
            name_off: u32_at(self.types, off)?,
            info: u32_at(self.types, off.checked_add(4)?)?,
            size_or_type: u32_at(self.types, off.checked_add(8)?)?,
        })
    }

    /// Type `id` and where its record starts, by the starts `at` that [`Self::types`] gave.
    fn get(&self, at: &[usize], id: u32) -> Option<(usize, TypeHdr)> {
        let off = *at.get(index(id).checked_sub(1)?)?;
        Some((off, self.hdr(off)?))
    }

    /// Type `id` with typedefs and modifiers (const, volatile, restrict, type tags) looked
    /// through.
    fn resolve(&self, at: &[usize], mut id: u32) -> Option<(usize, TypeHdr)> {
        for _ in 0..RESOLVE_MAX {
            let (off, t) = self.get(at, id)?;
            match t.kind() {
                // TYPEDEF, VOLATILE, CONST, RESTRICT, TYPE_TAG.
                8..=11 | 18 => id = t.size_or_type,
                _ => return Some((off, t)),
            }
        }
        None
    }

    /// Whether type `id` is a pointer to the struct `name`.
    fn points_to(&self, at: &[usize], id: u32, name: &[u8]) -> bool {
        self.resolve(at, id)
            .filter(|&(_, t)| t.kind() == KIND_PTR)
            .and_then(|(_, ptr)| self.resolve(at, ptr.size_or_type))
            .is_some_and(|(_, t)| t.kind() == KIND_STRUCT && self.name(t.name_off) == Some(name))
    }

    /// The prototype of function prototype `id`.
    fn prototype(&self, at: &[usize], id: u32) -> Option<Prototype> {
        let (off, proto) = self.get(at, id)?;
        if proto.kind() != KIND_FUNC_PROTO {
            return None;
        }
        let mut dentry = None;
        for i in 0..proto.vlen() {
            // {name_off, type} pairs after the header.
            let ty = u32_at(self.types, off + 16 + 8 * i)?;
            if self.points_to(at, ty, b"dentry") {
                dentry = Some(i);
            }
        }
        let ret = match proto.size_or_type {
            0 => Ret::Void,
            ty => self
                .resolve(at, ty)
                .map_or(Ret::Other, |(_, t)| match t.kind() {
                    KIND_INT | KIND_ENUM | KIND_ENUM64 => Ret::Int,
                    KIND_PTR => Ret::Pointer,
                    _ => Ret::Other,
                }),
        };
        Some(Prototype {
            params: proto.vlen(),
            dentry,
            ret,
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
    fn reads_the_prototypes_of_the_named_functions() {
        // Strings at 0 "", 1 "int", 5 "dentry", 12 "inode", 18 "f", 20 "g", 22 "h", 24 "a".
        let strings = b"\0int\0dentry\0inode\0f\0g\0h\0a\0";
        let types: [&[u32]; 14] = [
            // 1: INT int, with its encoding word.
            &[1, info(1, 0), 4, 32],
            // 2: STRUCT dentry {}.
            &[5, info(4, 0), 8],
            // 3: struct dentry *.
            &[0, info(2, 0), 2],
            // 4: const struct dentry, 5: const struct dentry *.
            &[0, info(10, 0), 2],
            &[0, info(2, 0), 4],
            // 6: STRUCT inode { int a; }: a member skipped by vlen. 7: struct inode *.
            &[12, info(4, 1), 4, 24, 1, 0],
            &[0, info(2, 0), 6],
            // 8: typedef struct dentry *a.
            &[24, info(8, 0), 3],
            // 9: int (struct inode *, struct dentry *, int).
            &[0, info(13, 3), 1, 0, 7, 0, 3, 0, 1],
            // 10: struct dentry *(const struct dentry *, struct inode *, a).
            &[0, info(13, 3), 3, 0, 5, 0, 7, 0, 8],
            // 11: void (int).
            &[0, info(13, 1), 0, 0, 1],
            // 12: FUNC f -> 9, 13: FUNC g -> 10, 14: FUNC h -> 11.
            &[18, info(12, 0), 9],
            &[20, info(12, 0), 10],
            &[22, info(12, 0), 11],
        ];
        let raw = btf(&types, strings);
        let f = Prototype {
            params: 3,
            dentry: Some(1),
            ret: Ret::Int,
        };
        // The last of two dentries, through a const and a typedef.
        let g = Prototype {
            params: 3,
            dentry: Some(2),
            ret: Ret::Pointer,
        };
        let h = Prototype {
            params: 1,
            dentry: None,
            ret: Ret::Void,
        };
        // A struct of a name asked for is not a function; answers keep the order asked.
        assert_eq!(
            prototypes(&raw, &["g", "inode", "f", "h", "x"]),
            [Some(g), None, Some(f), Some(h), None]
        );
        // Cut inside the string table.
        assert_eq!(prototypes(&raw[..raw.len() - 5], &["f"]), [None]);
    }
}
