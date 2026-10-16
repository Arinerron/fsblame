//! Selecting which changes to report, shared by live watching and offline queries.
//!
//! Criteria of different kinds must all hold; values within one kind are alternatives. An
//! empty kind places no constraint. `ignore_comm` excludes regardless of every other kind.

use std::path::Path;

use crate::glob::Glob;

/// Bytes of a thread name the kernel keeps (`TASK_COMM_LEN` minus the NUL).
const COMM_MAX: usize = 15;

/// systemd unit suffixes that a `unit` criterion may omit.
const UNIT_SUFFIXES: [&str; 2] = [".service", ".scope"];

/// Uncompiled filter criteria, as collected from flags or a query.
#[derive(Clone, Debug, Default)]
pub struct FilterSpec {
    /// Report a change if any of its paths matches any of these globs.
    pub include: Vec<Glob>,
    /// Report a change if the actor's `comm` is one of these.
    pub comm: Vec<String>,
    /// Never report a change whose actor's `comm` is one of these.
    pub ignore_comm: Vec<String>,
    /// Report a change if the actor's uid is one of these.
    pub uid: Vec<u32>,
    /// Report a change if the actor runs in one of these systemd units.
    pub unit: Vec<String>,
    /// Report a change if the actor's process id (tgid) is one of these.
    pub pid: Vec<u32>,
}

/// A compiled [`FilterSpec`].
#[derive(Clone, Debug, Default)]
pub struct Filter {
    /// Path globs; any match admits.
    include: Box<[Glob]>,
    /// Admitted `comm`s, cut to [`COMM_MAX`] bytes.
    comm: Box<[Box<[u8]>]>,
    /// Excluded `comm`s, cut to [`COMM_MAX`] bytes.
    ignore_comm: Box<[Box<[u8]>]>,
    /// Admitted uids.
    uid: Box<[u32]>,
    /// Admitted unit names, as given.
    unit: Box<[Box<str>]>,
    /// Admitted tgids.
    pid: Box<[u32]>,
}

/// What a [`Filter`] needs to know about one change.
#[derive(Clone, Copy, Debug)]
pub struct Candidate<'a> {
    /// The changed path, the old path of a rename, and a link or symlink target, when present.
    pub paths: [Option<&'a Path>; 3],
    /// The acting thread's `comm`.
    pub comm: &'a str,
    /// The actor's uid.
    pub uid: u32,
    /// The actor's process id (tgid, in the initial pid namespace).
    pub tgid: u32,
    /// The systemd unit owning the actor's cgroup, if any.
    pub unit: Option<&'a str>,
}

impl Filter {
    /// Compiles `spec`.
    pub fn new(spec: FilterSpec) -> Self {
        Self {
            include: spec.include.into(),
            comm: comm_keys(&spec.comm),
            ignore_comm: comm_keys(&spec.ignore_comm),
            uid: spec.uid.into(),
            unit: spec.unit.into_iter().map(String::into_boxed_str).collect(),
            pid: spec.pid.into(),
        }
    }

    /// Whether the filter admits everything.
    pub fn is_empty(&self) -> bool {
        self.include.is_empty()
            && self.comm.is_empty()
            && self.ignore_comm.is_empty()
            && self.uid.is_empty()
            && self.unit.is_empty()
            && self.pid.is_empty()
    }

    /// Whether the change described by `c` should be reported.
    ///
    /// `comm` criteria compare the first 15 bytes of both names, since the kernel keeps no
    /// more: `--comm cargo-build-script` matches the thread `cargo-build-scr`. A `unit`
    /// criterion matches the unit name exactly or with its `.service`/`.scope` suffix
    /// omitted. `pid` matches the actor's tgid.
    pub fn matches(&self, c: &Candidate<'_>) -> bool {
        let comm = comm_key(c.comm);
        (self.pid.is_empty() || self.pid.contains(&c.tgid))
            && (self.uid.is_empty() || self.uid.contains(&c.uid))
            && (self.comm.is_empty() || self.comm.iter().any(|name| **name == *comm))
            && !self.ignore_comm.iter().any(|name| **name == *comm)
            && (self.unit.is_empty()
                || c.unit
                    .is_some_and(|unit| self.unit.iter().any(|name| unit_is(unit, name))))
            && (self.include.is_empty()
                || c.paths
                    .iter()
                    .flatten()
                    .any(|path| self.include.iter().any(|glob| glob.matches(path))))
    }
}

/// The bytes of `name` the kernel would keep as a `comm`.
fn comm_key(name: &str) -> &[u8] {
    let bytes = name.as_bytes();
    &bytes[..bytes.len().min(COMM_MAX)]
}

/// The [`comm_key`] of each of `names`.
fn comm_keys(names: &[String]) -> Box<[Box<[u8]>]> {
    names.iter().map(|name| Box::from(comm_key(name))).collect()
}

/// Whether the systemd unit `unit` is the one named `name`, suffix optional.
fn unit_is(unit: &str, name: &str) -> bool {
    unit == name
        || UNIT_SUFFIXES
            .iter()
            .any(|suffix| unit.strip_suffix(suffix) == Some(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate<'a>(paths: [Option<&'a str>; 3], comm: &'a str) -> Candidate<'a> {
        Candidate {
            paths: paths.map(|p| p.map(Path::new)),
            comm,
            uid: 1000,
            tgid: 42,
            unit: Some("nginx.service"),
        }
    }

    fn base() -> Candidate<'static> {
        candidate([Some("/srv/www/index.html"), None, None], "nginx")
    }

    fn globs(patterns: &[&str]) -> Vec<Glob> {
        patterns
            .iter()
            .map(|p| Glob::new(p).expect("valid glob"))
            .collect()
    }

    fn strings(names: &[&str]) -> Vec<String> {
        names.iter().map(|&n| n.to_owned()).collect()
    }

    #[test]
    fn empty_filter_admits_everything() {
        let filter = Filter::new(FilterSpec::default());
        assert!(filter.is_empty());
        assert!(filter.matches(&base()));
        assert!(filter.matches(&candidate([None, None, None], "")));
    }

    #[test]
    fn any_criterion_makes_the_filter_non_empty() {
        let specs = [
            FilterSpec {
                include: globs(&["*"]),
                ..FilterSpec::default()
            },
            FilterSpec {
                comm: strings(&["a"]),
                ..FilterSpec::default()
            },
            FilterSpec {
                ignore_comm: strings(&["a"]),
                ..FilterSpec::default()
            },
            FilterSpec {
                uid: vec![0],
                ..FilterSpec::default()
            },
            FilterSpec {
                unit: strings(&["a"]),
                ..FilterSpec::default()
            },
            FilterSpec {
                pid: vec![1],
                ..FilterSpec::default()
            },
        ];
        for spec in specs {
            assert!(!Filter::new(spec).is_empty());
        }
    }

    #[test]
    fn values_within_a_kind_are_alternatives() {
        let filter = Filter::new(FilterSpec {
            comm: strings(&["make", "nginx"]),
            uid: vec![0, 1000],
            pid: vec![7, 42],
            ..FilterSpec::default()
        });
        assert!(filter.matches(&base()));
        assert!(filter.matches(&Candidate {
            uid: 0,
            tgid: 7,
            ..base()
        }));
        assert!(!filter.matches(&Candidate { uid: 1, ..base() }));
        assert!(!filter.matches(&Candidate { tgid: 43, ..base() }));
        assert!(!filter.matches(&Candidate {
            comm: "bash",
            ..base()
        }));
    }

    #[test]
    fn kinds_must_all_hold() {
        let filter = Filter::new(FilterSpec {
            include: globs(&["*.html"]),
            uid: vec![1000],
            ..FilterSpec::default()
        });
        assert!(filter.matches(&base()));
        assert!(!filter.matches(&Candidate { uid: 0, ..base() }));
        let css = candidate([Some("/srv/www/site.css"), None, None], "nginx");
        assert!(!filter.matches(&css));
    }

    #[test]
    fn include_checks_every_present_path() {
        let filter = Filter::new(FilterSpec {
            include: globs(&["/home/**", "*.lock"]),
            ..FilterSpec::default()
        });
        let renamed_out = candidate([Some("/tmp/x"), Some("/home/u/x"), None], "mv");
        assert!(filter.matches(&renamed_out));
        let link = candidate([Some("/srv/l"), None, Some("/srv/Cargo.lock")], "ln");
        assert!(filter.matches(&link));
        let elsewhere = candidate([Some("/tmp/x"), None, Some("/var/y")], "ln");
        assert!(!filter.matches(&elsewhere));
        assert!(!filter.matches(&candidate([None, None, None], "ln")));
    }

    #[test]
    fn ignore_comm_wins_over_everything() {
        let filter = Filter::new(FilterSpec {
            include: globs(&["**"]),
            comm: strings(&["nginx"]),
            ignore_comm: strings(&["nginx"]),
            ..FilterSpec::default()
        });
        assert!(!filter.matches(&base()));
        let only_ignore = Filter::new(FilterSpec {
            ignore_comm: strings(&["nginx", "git"]),
            ..FilterSpec::default()
        });
        assert!(!only_ignore.matches(&base()));
        assert!(only_ignore.matches(&Candidate {
            comm: "make",
            ..base()
        }));
    }

    #[test]
    fn comm_compares_the_kernel_kept_prefix() {
        let filter = Filter::new(FilterSpec {
            comm: strings(&["cargo-build-script"]),
            ..FilterSpec::default()
        });
        assert!(filter.matches(&Candidate {
            comm: "cargo-build-scr",
            ..base()
        }));
        assert!(!filter.matches(&Candidate {
            comm: "cargo-build-sc",
            ..base()
        }));
        assert!(!filter.matches(&Candidate {
            comm: "cargo",
            ..base()
        }));
        let ignore = Filter::new(FilterSpec {
            ignore_comm: strings(&["kworker/u16:0-events"]),
            ..FilterSpec::default()
        });
        assert!(!ignore.matches(&Candidate {
            comm: "kworker/u16:0-e",
            ..base()
        }));
        let exact = Filter::new(FilterSpec {
            comm: strings(&["make"]),
            ..FilterSpec::default()
        });
        assert!(!exact.matches(&Candidate {
            comm: "makefile",
            ..base()
        }));
        assert!(!exact.matches(&Candidate {
            comm: "mak",
            ..base()
        }));
    }

    #[test]
    fn unit_matches_with_or_without_suffix() {
        let filter = Filter::new(FilterSpec {
            unit: strings(&["nginx"]),
            ..FilterSpec::default()
        });
        assert!(filter.matches(&base()));
        assert!(filter.matches(&Candidate {
            unit: Some("nginx.scope"),
            ..base()
        }));
        assert!(!filter.matches(&Candidate {
            unit: Some("nginx.socket"),
            ..base()
        }));
        assert!(!filter.matches(&Candidate {
            unit: Some("nginx-debug.service"),
            ..base()
        }));
        assert!(!filter.matches(&Candidate {
            unit: None,
            ..base()
        }));
        let full = Filter::new(FilterSpec {
            unit: strings(&["nginx.service"]),
            ..FilterSpec::default()
        });
        assert!(full.matches(&base()));
        assert!(!full.matches(&Candidate {
            unit: Some("nginx.scope"),
            ..base()
        }));
        let socket = Filter::new(FilterSpec {
            unit: strings(&["nginx.socket"]),
            ..FilterSpec::default()
        });
        assert!(socket.matches(&Candidate {
            unit: Some("nginx.socket"),
            ..base()
        }));
    }
}
