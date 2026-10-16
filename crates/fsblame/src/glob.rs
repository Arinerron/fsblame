//! Path globs for selecting reported files.
//!
//! Linux paths are bytes, so patterns are matched byte-wise against
//! [`Path`]s without decoding. Syntax:
//!
//! | Pattern | Matches |
//! |---------|---------|
//! | `*` | any run of bytes within one path component |
//! | `**` | any number of whole components, including none; only as a full component |
//! | `?` | exactly one byte |
//! | `[abc]`, `[a-z]` | one byte from the set; members and range ends must be ASCII |
//! | `[!..]`, `[^..]` | one byte not in the set |
//! | `\x` | the byte `x` literally (`/` cannot be escaped) |
//!
//! Placement follows gitignore:
//!
//! - A pattern without `/`, such as `*.rs`, matches the final component anywhere.
//! - A pattern starting with `/`, such as `/etc/**`, is anchored to the absolute path.
//! - Any other pattern with `/`, such as `node_modules/**`, matches any trailing run of
//!   whole components: `/a/node_modules/x/y` matches.
//! - A trailing `/` means "this directory and everything below it": `build/` is `build/**`.
//!
//! Repeated `/` collapse. Matching is iterative with one fallback point per pattern level
//! (the most recent `*` or `**`), so it is polynomial in the worst case and linear for
//! patterns without wildcards; it never allocates.

use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::str::FromStr;

/// A compiled path glob.
#[derive(Clone, Debug)]
pub struct Glob {
    /// The pattern as written.
    source: Box<str>,
    /// Pattern components, in path order.
    parts: Box<[Part]>,
    /// How `parts` line up with a path.
    shape: Shape,
}

/// How a compiled pattern lines up with a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// The pattern started with `/`: it covers the whole absolute path.
    Anchored,
    /// The parts, none of them `**`, must match the path's last components.
    Suffix,
    /// The parts start with `**` and contain another: general component matching.
    Floating,
}

/// One `/`-separated pattern component.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Part {
    /// `**`: any number of whole components.
    Globstar,
    /// A component without wildcards, compared bytewise.
    Literal(Box<[u8]>),
    /// A component with wildcards.
    Wild(Box<[Token]>),
}

/// One element of a wildcard component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    /// That exact byte.
    Byte(u8),
    /// `?`: any byte.
    Any,
    /// `*`: any run of bytes.
    Star,
    /// `[..]`: one byte from the set.
    Class(ByteSet),
}

/// A set of bytes, one bit per value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ByteSet([u64; 4]);

/// Why a pattern does not compile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobError {
    /// The rejected pattern.
    pattern: Box<str>,
    /// Byte offset of the offending construct in `pattern`.
    offset: usize,
    /// What is wrong there.
    kind: GlobErrorKind,
}

/// The defect a [`GlobError`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GlobErrorKind {
    /// The pattern is empty.
    Empty,
    /// A `[` has no closing `]` within its path component.
    UnclosedClass,
    /// A class range runs backwards, such as `[z-a]`.
    ReversedRange,
    /// A class member is not ASCII; classes match single bytes.
    NonAsciiClass,
    /// `**` (or a longer run of `*`) is not a whole path component.
    Globstar,
    /// A `\` ends the pattern or escapes `/`.
    BadEscape,
}

impl Glob {
    /// Compiles `pattern`.
    pub fn new(pattern: &str) -> Result<Self, GlobError> {
        let fail = |offset, kind| GlobError {
            pattern: pattern.into(),
            offset,
            kind,
        };
        let bytes = pattern.as_bytes();
        let Some(&first) = bytes.first() else {
            return Err(fail(0, GlobErrorKind::Empty));
        };
        let anchored = first == b'/';
        let mut parts = Vec::new();
        if !anchored {
            parts.push(Part::Globstar);
        }
        let mut at = 0;
        while at < bytes.len() {
            if bytes[at] == b'/' {
                at += 1;
                continue;
            }
            let (part, end) =
                parse_component(bytes, at).map_err(|(offset, kind)| fail(offset, kind))?;
            push_part(&mut parts, part);
            at = end;
        }
        if bytes.ends_with(b"/") {
            push_part(&mut parts, Part::Globstar);
        }
        let shape = if anchored {
            Shape::Anchored
        } else if parts[1..].contains(&Part::Globstar) {
            Shape::Floating
        } else {
            parts.remove(0);
            Shape::Suffix
        };
        Ok(Self {
            source: pattern.into(),
            parts: parts.into_boxed_slice(),
            shape,
        })
    }

    /// The pattern as written.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Whether `path` matches.
    pub fn matches(&self, path: &Path) -> bool {
        self.matches_bytes(path.as_os_str().as_bytes())
    }

    /// Whether the raw path bytes `path` match.
    pub fn matches_bytes(&self, path: &[u8]) -> bool {
        match self.shape {
            Shape::Anchored => path.first() == Some(&b'/') && match_parts(&self.parts, path),
            Shape::Floating => match_parts(&self.parts, path),
            Shape::Suffix => match_suffix(&self.parts, path),
        }
    }
}

impl FromStr for Glob {
    type Err = GlobError;

    fn from_str(pattern: &str) -> Result<Self, GlobError> {
        Self::new(pattern)
    }
}

impl fmt::Display for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

impl GlobError {
    /// What is wrong with the pattern.
    pub fn kind(&self) -> GlobErrorKind {
        self.kind
    }

    /// Byte offset of the offending construct in the pattern.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Display for GlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            GlobErrorKind::Empty => "pattern is empty",
            GlobErrorKind::UnclosedClass => "`[` has no closing `]` in its path component",
            GlobErrorKind::ReversedRange => "class range runs backwards",
            GlobErrorKind::NonAsciiClass => "class members must be ASCII",
            GlobErrorKind::Globstar => "`**` must be a whole path component",
            GlobErrorKind::BadEscape => "`\\` must escape a byte other than `/`",
        };
        write!(
            f,
            "invalid glob `{}`: {what} (at byte {})",
            self.pattern, self.offset
        )
    }
}

impl std::error::Error for GlobError {}

impl Part {
    /// Whether this non-`**` part matches the component `name`.
    fn matches(&self, name: &[u8]) -> bool {
        match self {
            Self::Globstar => true,
            Self::Literal(literal) => **literal == *name,
            Self::Wild(tokens) => match_tokens(tokens, name),
        }
    }
}

impl Token {
    /// Whether this single-byte token matches `byte`; [`Token::Star`] never does.
    fn matches(self, byte: u8) -> bool {
        match self {
            Self::Byte(b) => b == byte,
            Self::Any => true,
            Self::Star => false,
            Self::Class(set) => set.contains(byte),
        }
    }
}

impl ByteSet {
    /// Adds every byte in `lo..=hi`.
    fn insert_range(&mut self, lo: u8, hi: u8) {
        for byte in lo..=hi {
            self.0[usize::from(byte >> 6)] |= 1 << (byte & 63);
        }
    }

    /// Replaces the set with its complement.
    fn invert(&mut self) {
        for word in &mut self.0 {
            *word = !*word;
        }
    }

    /// Whether `byte` is in the set.
    fn contains(self, byte: u8) -> bool {
        (self.0[usize::from(byte >> 6)] >> (byte & 63)) & 1 != 0
    }
}

/// Appends `part`, collapsing adjacent `**`.
fn push_part(parts: &mut Vec<Part>, part: Part) {
    if part == Part::Globstar && parts.last() == Some(&Part::Globstar) {
        return;
    }
    parts.push(part);
}

/// A compile error: byte offset and defect.
type ParseError = (usize, GlobErrorKind);

/// Parses the component starting at `start` (not `/`); returns it and the offset just past it.
fn parse_component(bytes: &[u8], start: usize) -> Result<(Part, usize), ParseError> {
    let mut tokens = Vec::new();
    let mut at = start;
    while let Some(&byte) = bytes.get(at)
        && byte != b'/'
    {
        match byte {
            b'*' => {
                let run = bytes[at..].iter().take_while(|&&b| b == b'*').count();
                let end = at + run;
                let whole = at == start && bytes.get(end).is_none_or(|&b| b == b'/');
                match run {
                    1 => tokens.push(Token::Star),
                    2 if whole => return Ok((Part::Globstar, end)),
                    _ => return Err((at, GlobErrorKind::Globstar)),
                }
                at = end;
            }
            b'?' => {
                tokens.push(Token::Any);
                at += 1;
            }
            b'[' => {
                let (set, end) = parse_class(bytes, at)?;
                tokens.push(Token::Class(set));
                at = end;
            }
            b'\\' => match bytes.get(at + 1) {
                Some(&escaped) if escaped != b'/' => {
                    tokens.push(Token::Byte(escaped));
                    at += 2;
                }
                _ => return Err((at, GlobErrorKind::BadEscape)),
            },
            _ => {
                tokens.push(Token::Byte(byte));
                at += 1;
            }
        }
    }
    let literal: Option<Box<[u8]>> = tokens
        .iter()
        .map(|token| match token {
            Token::Byte(b) => Some(*b),
            _ => None,
        })
        .collect();
    let part = match literal {
        Some(literal) => Part::Literal(literal),
        None => Part::Wild(tokens.into_boxed_slice()),
    };
    Ok((part, at))
}

/// Parses the class whose `[` is at `open`; returns it and the offset just past its `]`.
fn parse_class(bytes: &[u8], open: usize) -> Result<(ByteSet, usize), ParseError> {
    let mut at = open + 1;
    let negated = matches!(bytes.get(at), Some(b'!' | b'^'));
    if negated {
        at += 1;
    }
    let first = at;
    let mut set = ByteSet::default();
    loop {
        match bytes.get(at) {
            None => return Err((open, GlobErrorKind::UnclosedClass)),
            Some(b']') if at > first => break,
            Some(_) => {}
        }
        let (lo, next) = class_byte(bytes, at, open)?;
        at = next;
        let hi = if bytes.get(at) == Some(&b'-') && bytes.get(at + 1).is_some_and(|&b| b != b']') {
            let (hi, next) = class_byte(bytes, at + 1, open)?;
            if hi < lo {
                return Err((at, GlobErrorKind::ReversedRange));
            }
            at = next;
            hi
        } else {
            lo
        };
        set.insert_range(lo, hi);
    }
    if negated {
        set.invert();
    }
    Ok((set, at + 1))
}

/// Reads one class member at `at` (inside the class opened at `open`), honouring `\`.
fn class_byte(bytes: &[u8], at: usize, open: usize) -> Result<(u8, usize), ParseError> {
    let (byte, next) = match bytes.get(at) {
        None | Some(b'/') => return Err((open, GlobErrorKind::UnclosedClass)),
        Some(b'\\') => match bytes.get(at + 1) {
            Some(&escaped) if escaped != b'/' => (escaped, at + 2),
            _ => return Err((at, GlobErrorKind::BadEscape)),
        },
        Some(&byte) => (byte, at + 1),
    };
    if byte.is_ascii() {
        Ok((byte, next))
    } else {
        Err((next - 1, GlobErrorKind::NonAsciiClass))
    }
}

/// Matches one component against wildcard `tokens`, falling back to the latest `*`.
fn match_tokens(tokens: &[Token], name: &[u8]) -> bool {
    let (mut t, mut n) = (0, 0);
    // Token after the latest `*`, and the name offset that `*` currently stops at.
    let mut fallback = None;
    loop {
        match tokens.get(t) {
            Some(Token::Star) => {
                t += 1;
                if t == tokens.len() {
                    return true;
                }
                fallback = Some((t, n));
                continue;
            }
            Some(&token) if name.get(n).is_some_and(|&byte| token.matches(byte)) => {
                t += 1;
                n += 1;
                continue;
            }
            None if n == name.len() => return true,
            Some(_) | None => {}
        }
        match fallback {
            Some((after, stop)) if stop < name.len() => {
                fallback = Some((after, stop + 1));
                t = after;
                n = stop + 1;
            }
            _ => return false,
        }
    }
}

/// The non-empty `/`-separated components left in a path.
#[derive(Clone, Copy)]
struct Components<'a>(&'a [u8]);

impl<'a> Components<'a> {
    /// The next component and the components after it; `None` when none remain.
    fn split_first(self) -> Option<(&'a [u8], Self)> {
        let start = self.0.iter().position(|&b| b != b'/')?;
        let rest = &self.0[start..];
        let end = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
        let (component, tail) = rest.split_at(end);
        Some((component, Self(tail)))
    }

    /// Whether no component remains.
    fn is_done(self) -> bool {
        self.0.iter().all(|&b| b == b'/')
    }
}

/// Matches `parts` against every component of `path`, falling back to the latest `**`.
fn match_parts(parts: &[Part], path: &[u8]) -> bool {
    let mut p = 0;
    let mut rest = Components(path);
    // Part after the latest `**`, and the components left after what that `**` swallows.
    let mut fallback: Option<(usize, Components<'_>)> = None;
    loop {
        match parts.get(p) {
            Some(Part::Globstar) => {
                p += 1;
                if p == parts.len() {
                    return true;
                }
                fallback = Some((p, rest));
                continue;
            }
            Some(part) => {
                if let Some((component, after)) = rest.split_first()
                    && part.matches(component)
                {
                    p += 1;
                    rest = after;
                    continue;
                }
            }
            None if rest.is_done() => return true,
            None => {}
        }
        let Some((after, swallowed)) = fallback else {
            return false;
        };
        let Some((_, swallowed)) = swallowed.split_first() else {
            return false;
        };
        fallback = Some((after, swallowed));
        p = after;
        rest = swallowed;
    }
}

/// Matches `parts` (none of them `**`) against the last components of `path`.
fn match_suffix(parts: &[Part], path: &[u8]) -> bool {
    let mut components = path.rsplit(|&b| b == b'/').filter(|c| !c.is_empty());
    parts.iter().rev().all(|part| {
        components
            .next()
            .is_some_and(|component| part.matches(component))
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::time::{Duration, Instant};

    use super::*;

    fn glob(pattern: &str) -> Glob {
        Glob::new(pattern).unwrap_or_else(|e| panic!("{e}"))
    }

    fn matches(pattern: &str, path: &str) -> bool {
        glob(pattern).matches(Path::new(path))
    }

    fn error(pattern: &str) -> (GlobErrorKind, usize) {
        let e = Glob::new(pattern).expect_err(pattern);
        (e.kind(), e.offset())
    }

    #[test]
    fn basename_patterns_match_the_final_component_anywhere() {
        assert!(matches("*.rs", "/src/main.rs"));
        assert!(matches("*.rs", "/a/b/c/lib.rs"));
        assert!(matches("*.rs", "main.rs"));
        assert!(matches("Cargo.toml", "/x/Cargo.toml"));
        assert!(!matches("*.rs", "/src/main.rs/x"));
        assert!(!matches("*.rs", "/src.rs/main.c"));
        assert!(!matches("main", "/src/main.rs"));
        assert!(!matches("*.rs", "/"));
        assert!(!matches("*.rs", ""));
        assert!(matches("*", "/a"));
        assert!(!matches("*", "/"));
    }

    #[test]
    fn anchored_patterns_cover_the_whole_absolute_path() {
        assert!(matches("/etc/passwd", "/etc/passwd"));
        assert!(matches("/etc/passwd", "//etc//passwd"));
        assert!(!matches("/etc/passwd", "/chroot/etc/passwd"));
        assert!(!matches("/etc/passwd", "/etc/passwd/x"));
        assert!(!matches("/etc/passwd", "etc/passwd"));
        assert!(matches("/etc/*.conf", "/etc/a.conf"));
        assert!(!matches("/etc/*.conf", "/etc/sub/a.conf"));
        assert!(matches("/", "/anything/below"));
        assert!(matches("/", "/"));
        assert!(!matches("/", "relative"));
    }

    #[test]
    fn relative_patterns_with_a_slash_match_trailing_components() {
        assert!(matches("src/*.rs", "/home/u/proj/src/main.rs"));
        assert!(matches("src/*.rs", "src/main.rs"));
        assert!(!matches("src/*.rs", "/home/u/proj/src/bin/main.rs"));
        assert!(!matches("src/*.rs", "/home/u/proj/xsrc/main.rs"));
        assert!(matches("node_modules/**", "/a/node_modules/x/y"));
        assert!(matches("node_modules/**", "/a/node_modules"));
        assert!(!matches("node_modules/**", "/a/node_modules2/x"));
        assert!(matches("a/b", "/x/a/b"));
        assert!(!matches("a/b", "/x/a/b/c"));
    }

    #[test]
    fn trailing_slash_means_everything_below() {
        assert!(matches("build/", "/p/build/out/a.o"));
        assert!(matches("build/", "/p/build"));
        assert!(!matches("build/", "/p/builds/a"));
        assert!(matches("/tmp/", "/tmp/x"));
        assert!(!matches("/tmp/", "/var/tmp/x"));
    }

    #[test]
    fn globstar_at_start_middle_and_end() {
        assert!(matches("**/x.rs", "/x.rs"));
        assert!(matches("**/x.rs", "/a/b/x.rs"));
        assert!(matches("/**/x.rs", "/x.rs"));
        assert!(matches("/**/x.rs", "/a/b/c/x.rs"));
        assert!(!matches("/**/x.rs", "/a/b/c/x.rsx"));
        assert!(matches("/a/**/z", "/a/z"));
        assert!(matches("/a/**/z", "/a/b/c/z"));
        assert!(!matches("/a/**/z", "/a/b/c/z/q"));
        assert!(!matches("/a/**/z", "/b/a/z"));
        assert!(matches("/a/**", "/a"));
        assert!(matches("/a/**", "/a/b/c"));
        assert!(!matches("/a/**", "/ab/c"));
        assert!(matches("**", "/anything"));
        assert!(matches("**", "/"));
        assert!(matches("a/**/b/**/c", "/x/a/1/b/2/3/c"));
        assert!(matches("a/**/b/**/c", "/a/b/c"));
        assert!(!matches("a/**/b/**/c", "/a/c/b"));
        assert!(matches("/**/**/x", "/x"));
    }

    #[test]
    fn single_byte_wildcards_and_stars_stay_within_a_component() {
        assert!(matches("?.c", "/a.c"));
        assert!(!matches("?.c", "/ab.c"));
        assert!(matches("/a?c", "/abc"));
        assert!(!matches("/a?c", "/a/c"));
        assert!(!matches("/a*c", "/a/c"));
        assert!(matches("a*b*c", "/aXbYc"));
        assert!(matches("a*b*c", "/abc"));
        assert!(matches("*a*", "/bab"));
        assert!(!matches("a*b", "/aXbY"));
        assert!(matches("*", "/.hidden"));
    }

    #[test]
    fn classes_ranges_and_negation() {
        assert!(matches("[abc].txt", "/b.txt"));
        assert!(!matches("[abc].txt", "/d.txt"));
        assert!(matches("file[0-9]", "/file7"));
        assert!(!matches("file[0-9]", "/filex"));
        assert!(matches("[a-cx-z]", "/y"));
        assert!(!matches("[a-cx-z]", "/m"));
        assert!(matches("[!a-c]", "/d"));
        assert!(!matches("[!a-c]", "/b"));
        assert!(matches("[^a-c]", "/d"));
        assert!(!matches("[^a-c]", "/a"));
        assert!(matches("[]]", "/]"));
        assert!(matches("[!]]", "/a"));
        assert!(!matches("[!]]", "/]"));
        assert!(matches("[a-]", "/-"));
        assert!(matches("[-a]", "/-"));
        assert!(matches("[\\]]", "/]"));
        assert!(matches("[\\!]", "/!"));
        assert!(!matches("[!a]", "/\u{e9}"));
    }

    #[test]
    fn escapes_make_metacharacters_literal() {
        assert!(matches("\\*", "/*"));
        assert!(!matches("\\*", "/a"));
        assert!(matches("\\?x", "/?x"));
        assert!(!matches("\\?x", "/ax"));
        assert!(matches("\\[a]", "/[a]"));
        assert!(matches("a\\\\b", "/a\\b"));
        assert!(matches("\\**", "/*abc"));
    }

    #[test]
    fn non_utf8_paths_match_bytewise() {
        let path = Path::new(OsStr::from_bytes(b"/dir/caf\xe9.txt"));
        assert!(glob("*.txt").matches(path));
        assert!(glob("caf?.txt").matches(path));
        assert!(glob("[!a]*").matches(Path::new(OsStr::from_bytes(b"/\xff\xfe"))));
        assert!(glob("/dir/**").matches(path));
        assert!(glob("caf\u{e9}").matches_bytes("/x/caf\u{e9}".as_bytes()));
        assert!(!glob("caf?").matches_bytes("/x/caf\u{e9}".as_bytes()));
        assert!(glob("caf??").matches_bytes("/x/caf\u{e9}".as_bytes()));
    }

    #[test]
    fn rejects_malformed_patterns() {
        assert_eq!(error(""), (GlobErrorKind::Empty, 0));
        assert_eq!(error("a[bc"), (GlobErrorKind::UnclosedClass, 1));
        assert_eq!(error("[]"), (GlobErrorKind::UnclosedClass, 0));
        assert_eq!(error("x/[a/b]"), (GlobErrorKind::UnclosedClass, 2));
        assert_eq!(error("[z-a]"), (GlobErrorKind::ReversedRange, 2));
        assert_eq!(error("[\u{e9}]"), (GlobErrorKind::NonAsciiClass, 1));
        assert_eq!(error("a**"), (GlobErrorKind::Globstar, 1));
        assert_eq!(error("**a"), (GlobErrorKind::Globstar, 0));
        assert_eq!(error("/x/***/y"), (GlobErrorKind::Globstar, 3));
        assert_eq!(error("a\\"), (GlobErrorKind::BadEscape, 1));
        assert_eq!(error("a\\/b"), (GlobErrorKind::BadEscape, 1));
        assert_eq!(error("[\\/]"), (GlobErrorKind::BadEscape, 1));
        let message = Glob::new("a[").expect_err("unclosed").to_string();
        assert!(message.contains("a["), "{message}");
    }

    #[test]
    fn display_and_from_str_round_trip_the_source() {
        let g: Glob = "src//*.rs".parse().expect("valid");
        assert_eq!(g.to_string(), "src//*.rs");
        assert_eq!(g.as_str(), "src//*.rs");
    }

    #[test]
    fn pathological_patterns_finish_quickly() {
        let started = Instant::now();
        let long = format!("/{}", "a".repeat(10_000));
        assert!(!glob("a*a*a*a*a*a*a*a*b").matches_bytes(long.as_bytes()));
        assert!(glob("a*a*a*a*a*a*a*a*a").matches_bytes(long.as_bytes()));
        let deep = "/a".repeat(2_000);
        assert!(!glob("**/a/**/a/**/a/**/a/**/b").matches_bytes(deep.as_bytes()));
        assert!(glob("/**/a/**/a/**/a/**/a").matches_bytes(deep.as_bytes()));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
