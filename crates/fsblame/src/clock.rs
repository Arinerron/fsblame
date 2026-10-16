//! Event clock (`CLOCK_BOOTTIME`) to wall-clock conversion and formatting.

use std::num::NonZeroU64;

const NANOS: i128 = 1_000_000_000;

fn clock_ns(clock: libc::clockid_t) -> i128 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec.
    let rc = unsafe { libc::clock_gettime(clock, &raw mut ts) };
    assert_eq!(
        rc, 0,
        "clock_gettime({clock}) cannot fail for a supported clock"
    );
    i128::from(ts.tv_sec) * NANOS + i128::from(ts.tv_nsec)
}

/// Now, in the event clock (`bpf_ktime_get_boot_ns`).
pub fn boot_now_ns() -> u64 {
    u64::try_from(clock_ns(libc::CLOCK_BOOTTIME)).unwrap_or(0)
}

/// Kernel `USER_HZ` from the auxiliary vector, for `/proc` start times.
pub fn clock_ticks_per_sec() -> NonZeroU64 {
    // SAFETY: getauxval only reads the process's auxiliary vector.
    let hz = unsafe { libc::getauxval(libc::AT_CLKTCK) };
    // Linux has exported AT_CLKTCK since 2.6; USER_HZ is 100 on every architecture it runs on.
    NonZeroU64::new(hz).unwrap_or(NonZeroU64::new(100).expect("non-zero"))
}

/// Converts event timestamps to wall-clock time, using the offset between
/// `CLOCK_REALTIME` and `CLOCK_BOOTTIME` sampled at start-up.
#[derive(Clone, Copy, Debug)]
pub struct Clock {
    offset_ns: i128,
}

impl Clock {
    /// Samples the clock offset now.
    pub fn new() -> Self {
        let boot = clock_ns(libc::CLOCK_BOOTTIME);
        let real = clock_ns(libc::CLOCK_REALTIME);
        Self {
            offset_ns: real - boot,
        }
    }

    /// Unix time in nanoseconds of an event timestamp.
    pub fn unix_ns(self, boot_ns: u64) -> i128 {
        i128::from(boot_ns) + self.offset_ns
    }

    /// Local `HH:MM:SS` of an event timestamp.
    pub fn local_hms(self, boot_ns: u64) -> String {
        // `time_t` is `c_long` in the libc crate on every Linux target fsblame builds for.
        let secs = libc::c_long::try_from(self.unix_ns(boot_ns).div_euclid(NANOS)).unwrap_or(0);
        // SAFETY: an all-zero `tm` is valid (null `tm_zone`), and localtime_r only writes it.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: both pointers are valid for the call; `secs` has time_t's layout.
        if unsafe { libc::localtime_r((&raw const secs).cast(), &raw mut tm) }.is_null() {
            return rfc3339(self.unix_ns(boot_ns))[11..19].to_owned();
        }
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }

    /// RFC 3339 UTC time with microseconds, e.g. `2026-10-16T14:02:11.123456Z`.
    pub fn rfc3339(self, boot_ns: u64) -> String {
        rfc3339(self.unix_ns(boot_ns))
    }
}

/// RFC 3339 UTC rendering of Unix nanoseconds.
fn rfc3339(unix_ns: i128) -> String {
    let secs = i64::try_from(unix_ns.div_euclid(NANOS)).unwrap_or(0);
    let micros = unix_ns.rem_euclid(NANOS) / 1000;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Proleptic Gregorian date of a day count since 1970-01-01 (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).expect("1..=31");
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).expect("1..=12");
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::rfc3339;

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000000Z");
        // 2000-02-29 (leap day) 12:34:56.789012
        assert_eq!(
            rfc3339(951_827_696_789_012_345),
            "2000-02-29T12:34:56.789012Z"
        );
        assert_eq!(
            rfc3339(1_791_986_531_000_000_000),
            "2026-10-14T14:02:11.000000Z"
        );
        assert_eq!(rfc3339(-1_000_000_000), "1969-12-31T23:59:59.000000Z");
    }
}
