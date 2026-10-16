//! Event clock (`CLOCK_BOOTTIME`) to wall-clock conversion, and wall-clock formatting and
//! parsing.

use std::{fmt, num::NonZeroU64};

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

/// `USER_HZ` on every architecture Linux runs on, for kernels without `AT_CLKTCK`.
const DEFAULT_USER_HZ: NonZeroU64 = NonZeroU64::new(100).unwrap();

/// Kernel `USER_HZ` from the auxiliary vector, for `/proc` start times.
pub fn clock_ticks_per_sec() -> NonZeroU64 {
    // SAFETY: getauxval only reads the process's auxiliary vector.
    let hz = unsafe { libc::getauxval(libc::AT_CLKTCK) };
    // Linux has exported AT_CLKTCK since 2.6; the fallback only guards a zero.
    NonZeroU64::new(hz).unwrap_or(DEFAULT_USER_HZ)
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
}

impl Default for Clock {
    /// Samples the clock offset now, as [`Clock::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// Local `HH:MM:SS` of Unix nanoseconds.
pub fn local_hms(unix_ns: i128) -> String {
    // `time_t` is `c_long` in the libc crate on every Linux target fsblame builds for.
    let secs = libc::c_long::try_from(unix_ns.div_euclid(NANOS)).unwrap_or(0);
    // SAFETY: an all-zero `tm` is valid (null `tm_zone`), and localtime_r only writes it.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call; `secs` has time_t's layout.
    if unsafe { libc::localtime_r((&raw const secs).cast(), &raw mut tm) }.is_null() {
        return Rfc3339(unix_ns).to_string()[11..19].to_owned();
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

/// Unix nanoseconds displayed as RFC 3339 UTC time with microseconds, such as
/// `2026-10-16T14:02:11.123456Z`; [`parse_rfc3339`] reads it back.
#[derive(Clone, Copy, Debug)]
pub struct Rfc3339(pub i128);

impl fmt::Display for Rfc3339 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = i64::try_from(self.0.div_euclid(NANOS)).unwrap_or(0);
        let micros = self.0.rem_euclid(NANOS) / 1000;
        let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
        let (year, month, day) = civil_from_days(days);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
            rem / 3600,
            rem % 3600 / 60,
            rem % 60
        )
    }
}

/// Unix nanoseconds of an RFC 3339 time: `YYYY-MM-DDTHH:MM:SS`, an optional fraction of up
/// to nine digits, then `Z` or a `±HH:MM` offset. `None` if `text` is not one.
pub fn parse_rfc3339(text: &str) -> Option<i128> {
    /// The decimal number in `text`, which must be all ASCII digits.
    fn number(text: &str) -> Option<i64> {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    }
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let field = |range: std::ops::Range<usize>| text.get(range).and_then(number);
    let year = field(0..4)?;
    let month = u32::try_from(field(5..7)?).ok()?;
    let day = u32::try_from(field(8..10)?).ok()?;
    let (hour, minute, second) = (field(11..13)?, field(14..16)?, field(17..19)?);
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;

    let mut rest = &text[19..];
    let mut nanos: i128 = 0;
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(fraction.len());
        if digits == 0 || digits > 9 {
            return None;
        }
        // Scale to nanoseconds: one factor of ten per missing digit.
        nanos = (digits..9).fold(i128::from(number(&fraction[..digits])?), |n, _| n * 10);
        rest = &fraction[digits..];
    }
    let offset_secs = match rest.as_bytes() {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let (hours, minutes) = (number(&rest[1..3])?, number(&rest[4..6])?);
            if hours > 23 || minutes > 59 {
                return None;
            }
            let offset = hours * 3600 + minutes * 60;
            if *sign == b'-' { -offset } else { offset }
        }
        _ => return None,
    };
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs;
    Some(i128::from(secs) * NANOS + nanos)
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

/// Day count since 1970-01-01 of a proleptic Gregorian date; `None` for a date that does not
/// exist, such as February 30.
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    (civil_from_days(days) == (year, month, day)).then_some(days)
}

#[cfg(test)]
mod tests {
    use super::{Rfc3339, parse_rfc3339};

    #[test]
    fn rfc3339_matches_known_instants() {
        let text = |ns| Rfc3339(ns).to_string();
        assert_eq!(text(0), "1970-01-01T00:00:00.000000Z");
        // 2000-02-29 (leap day) 12:34:56.789012
        assert_eq!(text(951_827_696_789_012_345), "2000-02-29T12:34:56.789012Z");
        assert_eq!(
            text(1_791_986_531_000_000_000),
            "2026-10-14T14:02:11.000000Z"
        );
        assert_eq!(text(-1_000_000_000), "1969-12-31T23:59:59.000000Z");
    }

    #[test]
    fn rfc3339_parses_back_to_the_microsecond() {
        for ns in [
            0,
            951_827_696_789_012_000,
            1_791_986_531_000_000_000,
            -1_000_000_000,
        ] {
            assert_eq!(parse_rfc3339(&Rfc3339(ns).to_string()), Some(ns));
        }
        assert_eq!(
            parse_rfc3339("2026-10-14T16:02:11.5+02:00"),
            Some(1_791_986_531_500_000_000)
        );
        assert_eq!(
            parse_rfc3339("2026-10-14T14:02:11Z"),
            Some(1_791_986_531_000_000_000)
        );
        for bad in [
            "",
            "2026-10-14 14:02:11Z",
            "2026-02-30T00:00:00Z",
            "2026-10-14T24:00:00Z",
            "2026-10-14T14:02:11",
            "2026-10-14T14:02:11.Z",
            "2026-10-14T14:02:11.1234567890Z",
            "2026-10-14T14:02:11+0200",
            "+026-10-14T14:02:11Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad:?}");
        }
    }
}
