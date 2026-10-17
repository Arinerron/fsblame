//! `cargo xtask licenses [FILE]`: the third-party notices of the release binary.
//!
//! The static `fsblame` binary links every crate it depends on and embeds BPF objects
//! compiled against the vendored libbpf headers; their licenses (MIT, Apache-2.0, BSD,
//! Zlib, ...) ask that their notices travel with it. This writes them to one Markdown file
//! from `cargo metadata` (the release targets' dependency graph) and the license files each
//! package ships in its source directory (cargo registry, git checkout or path).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail, ensure};
use serde_json::Value;

use crate::USAGE;

/// The targets release binaries are built for; their dependency graphs are merged.
const TARGETS: [&str; 2] = ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"];
/// The package whose binary ships.
const BINARY_PACKAGE: &str = "fsblame";
/// Vendored libbpf headers compiled into the embedded BPF objects, relative to the
/// workspace root, with the license file copied from the libbpf release beside them.
const LIBBPF_DIR: &str = "crates/fsblame-bpf/bpf/include/bpf";
const LIBBPF_VERSION: &str = "1.8.0";
/// File name prefixes (upper-cased) of license and notice files.
const LICENSE_PREFIXES: [&str; 6] = [
    "LICENSE",
    "LICENCE",
    "COPYING",
    "UNLICENSE",
    "NOTICE",
    "COPYRIGHT",
];

/// One third-party component of the binary.
#[derive(Debug)]
struct Component {
    name: String,
    version: String,
    license: String,
    source: String,
    /// License files: name → text.
    files: Vec<(String, String)>,
}

/// Writes the notices to FILE (default `$CARGO_TARGET_DIR/THIRD_PARTY_LICENSES.md`, else
/// `target/THIRD_PARTY_LICENSES.md`).
pub fn licenses(args: &[OsString]) -> Result<bool> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("workspace root")?;
    let file = match args {
        [] => std::env::var_os("CARGO_TARGET_DIR")
            .map_or_else(|| root.join("target"), PathBuf::from)
            .join("THIRD_PARTY_LICENSES.md"),
        [file] => PathBuf::from(file),
        [_, extra, ..] => bail!("unexpected argument {}\n{USAGE}", extra.display()),
    };
    let mut components = BTreeMap::new();
    for target in TARGETS {
        for component in crates(root, target)? {
            components
                .entry((component.name.clone(), component.version.clone()))
                .or_insert(component);
        }
    }
    let mut components: Vec<Component> = components.into_values().collect();
    components.push(libbpf(root)?);
    let text = render(&components);
    if let Some(dir) = file.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(&file, text).with_context(|| format!("writing {}", file.display()))?;
    println!("{} ({} components)", file.display(), components.len());
    Ok(true)
}

/// The third-party crates in the binary's graph for `target`: the normal dependencies of
/// [`BINARY_PACKAGE`], transitively, plus those of first-party build scripts (whose output,
/// the BPF objects and their generated header, is embedded). Procedural macros and their
/// dependencies are included: they run at compile time, but generate code that ships.
fn crates(root: &Path, target: &str) -> Result<Vec<Component>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .current_dir(root)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--filter-platform",
            target,
        ])
        .stderr(Stdio::inherit())
        .output()
        .context("running cargo metadata")?;
    ensure!(out.status.success(), "cargo metadata failed");
    let meta: Value = serde_json::from_slice(&out.stdout).context("parsing cargo metadata")?;

    let packages: HashMap<&str, &Value> = meta["packages"]
        .as_array()
        .context("cargo metadata: packages")?
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p)))
        .collect();
    let members: BTreeSet<&str> = meta["workspace_members"]
        .as_array()
        .context("cargo metadata: workspace_members")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let nodes: HashMap<&str, &Value> = meta["resolve"]["nodes"]
        .as_array()
        .context("cargo metadata: resolve")?
        .iter()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();
    let binary = packages
        .values()
        .find(|p| p["name"] == BINARY_PACKAGE && members.contains(p["id"].as_str().unwrap_or("")))
        .and_then(|p| p["id"].as_str())
        .with_context(|| format!("package {BINARY_PACKAGE} not in the workspace"))?;

    let mut seen = BTreeSet::new();
    let mut stack = vec![binary];
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = nodes
            .get(id)
            .with_context(|| format!("no resolve node for {id}"))?;
        let first_party = members.contains(id);
        for dep in node["deps"].as_array().into_iter().flatten() {
            let follow = dep["dep_kinds"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|kind| match kind["kind"].as_str() {
                    None => true,
                    Some("build") => first_party,
                    Some(_) => false,
                });
            if follow && let Some(pkg) = dep["pkg"].as_str() {
                stack.push(pkg);
            }
        }
    }

    seen.into_iter()
        .filter(|id| !members.contains(id))
        .map(|id| {
            let pkg = packages
                .get(id)
                .with_context(|| format!("no package {id}"))?;
            component(root, pkg)
        })
        .collect()
}

/// A third-party package of `cargo metadata` with the license files in its source directory.
fn component(root: &Path, pkg: &Value) -> Result<Component> {
    let name = pkg["name"].as_str().context("package name")?.to_owned();
    let version = pkg["version"]
        .as_str()
        .context("package version")?
        .to_owned();
    let manifest = PathBuf::from(pkg["manifest_path"].as_str().context("manifest path")?);
    let dir = manifest.parent().context("manifest directory")?;
    let mut paths = license_files(dir)?;
    if let Some(file) = pkg["license_file"].as_str() {
        let path = dir.join(file);
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    if paths.is_empty() {
        bail!(
            "{name} {version} ships no license file in {}: add its license text by hand",
            dir.display()
        );
    }
    let files = paths
        .iter()
        .map(|path| read_text(dir, path))
        .collect::<Result<_>>()?;
    let source = match pkg["repository"].as_str() {
        Some(repo) => repo.to_owned(),
        None if pkg["source"].is_null() => {
            format!("{} (path)", dir.strip_prefix(root).unwrap_or(dir).display())
        }
        None => "crates.io".to_owned(),
    };
    let license = match pkg["license"].as_str() {
        Some(license) => license.replace('/', " OR "),
        None => "see license file".to_owned(),
    };
    Ok(Component {
        name,
        version,
        license,
        source,
        files,
    })
}

/// The vendored libbpf headers (`LGPL-2.1 OR BSD-2-Clause`, used under BSD-2-Clause).
fn libbpf(root: &Path) -> Result<Component> {
    let dir = root.join(LIBBPF_DIR);
    let files = license_files(&dir)?
        .iter()
        .map(|path| read_text(&dir, path))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        files.iter().any(|(name, _)| name == "LICENSE.BSD-2-Clause"),
        "{} lacks libbpf's LICENSE.BSD-2-Clause",
        dir.display()
    );
    Ok(Component {
        name: "libbpf headers".to_owned(),
        version: LIBBPF_VERSION.to_owned(),
        license: "LGPL-2.1 OR BSD-2-Clause (used under BSD-2-Clause)".to_owned(),
        source: "https://github.com/libbpf/libbpf".to_owned(),
        files,
    })
}

/// License and notice files directly in `dir`, sorted by name.
fn license_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_uppercase();
        if LICENSE_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
            && entry.path().is_file()
        {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

/// `(name relative to dir, text)` of a license file.
fn read_text(dir: &Path, path: &Path) -> Result<(String, String)> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    ensure!(!text.trim().is_empty(), "{} is empty", path.display());
    let name = path.strip_prefix(dir).unwrap_or(path).display().to_string();
    Ok((name, text))
}

/// Texts compare equal when they differ only in trailing whitespace and blank lines around
/// them (indentation stays: the Apache-2.0 title is centered with spaces).
fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines().skip_while(|line| line.trim().is_empty()) {
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out.truncate(out.trim_end().len());
    out.push('\n');
    out
}

/// The Markdown file: a table of the components, then each distinct license text once,
/// with the components that ship it.
fn render(components: &[Component]) -> String {
    // Distinct texts in order of first use; per component, the text numbers of its files.
    let mut texts: Vec<(String, Vec<String>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut refs: Vec<Vec<usize>> = Vec::new();
    for component in components {
        let mut mine = Vec::new();
        for (name, text) in &component.files {
            let key = normalize(text);
            let n = *index.entry(key.clone()).or_insert_with(|| {
                texts.push((key, Vec::new()));
                texts.len() - 1
            });
            texts[n].1.push(format!(
                "{} {} (`{name}`)",
                component.name, component.version
            ));
            mine.push(n);
        }
        refs.push(mine);
    }

    let mut out = String::new();
    out.push_str("# Third-party licenses\n\n");
    out.push_str(
        "fsblame is MIT licensed (see `LICENSE`). Its release binary is statically linked and \
         includes code from the components below, which are distributed under their own \
         licenses. Each component's license texts, as shipped in its source, follow the \
         table; texts shared by several components are printed once.\n\n",
    );
    out.push_str(
        "Generated by `cargo xtask licenses` from `Cargo.lock` for the \
         x86_64 and aarch64 musl release targets. Crates are the normal dependencies of the \
         `fsblame` package and of its BPF build step, including procedural macros, whose \
         generated code is compiled in. The libbpf headers are compiled into the BPF objects \
         the binary embeds; fsblame uses them under the BSD-2-Clause option of their dual \
         license.\n\n",
    );
    out.push_str("| Component | Version | License | Source | Texts |\n|---|---|---|---|---|\n");
    for (component, mine) in components.iter().zip(&refs) {
        let links = mine
            .iter()
            .map(|n| format!("[{}](#text-{})", n + 1, n + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {links} |",
            component.name, component.version, component.license, component.source
        );
    }
    out.push_str("\n## License texts\n");
    for (n, (text, users)) in texts.iter().enumerate() {
        let fence = if text.contains("```") { "~~~~" } else { "```" };
        let _ = write!(
            out,
            "\n### Text {}\n\nUsed by: {}.\n\n{fence}text\n{text}{fence}\n",
            n + 1,
            users.join(", ")
        );
    }
    out
}
