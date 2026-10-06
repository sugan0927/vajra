//! Allocation-free RFC 9110 `Date:` header formatting with a 1-second cache.
//!
//! `SystemTime::now()` goes through the vDSO (no real syscall), and we only
//! reformat when the wall-clock second changes, so under load the cost of the
//! Date header is one clock read per event-loop iteration.

use std::time::{SystemTime, UNIX_EPOCH};

const DAYS: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Length of an IMF-fixdate: `Sun, 06 Nov 1994 08:49:37 GMT`.
pub const DATE_LEN: usize = 29;

/// Per-core cache of the formatted date. Not `Sync` on purpose: share-nothing.
pub struct DateCache {
    sec: u64,
    buf: [u8; DATE_LEN],
}

impl Default for DateCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DateCache {
    pub fn new() -> Self {
        Self { sec: u64::MAX, buf: [b' '; DATE_LEN] }
    }

    /// Unix seconds as of the last [`get`](Self::get) call.
    #[inline]
    pub fn now_secs(&self) -> u64 {
        self.sec
    }

    /// Returns the current date, reformatting only if the second changed.
    #[inline]
    pub fn get(&mut self) -> &[u8; DATE_LEN] {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now != self.sec {
            format_http_date(now, &mut self.buf);
            self.sec = now;
        }
        &self.buf
    }
}

/// Format `unix_secs` as an IMF-fixdate into `out`.
pub fn format_http_date(unix_secs: u64, out: &mut [u8; DATE_LEN]) {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // 1970-01-01 was a Thursday (index 4 with Sunday = 0).
    let wd = ((days + 4) % 7) as usize;
    let (y, m, d) = civil_from_days(days);

    out[0..3].copy_from_slice(DAYS[wd]);
    out[3..5].copy_from_slice(b", ");
    put2(&mut out[5..7], d as u64);
    out[7] = b' ';
    out[8..11].copy_from_slice(MONTHS[(m - 1) as usize]);
    out[11] = b' ';
    put4(&mut out[12..16], y as u64);
    out[16] = b' ';
    put2(&mut out[17..19], h);
    out[19] = b':';
    put2(&mut out[20..22], mi);
    out[22] = b':';
    put2(&mut out[23..25], s);
    out[25..29].copy_from_slice(b" GMT");
}

/// Length of a Common Log Format timestamp: `[06/Nov/1994:08:49:37 +0000]`.
pub const CLF_LEN: usize = 28;

/// Format `unix_secs` as a CLF timestamp (always UTC).
pub fn format_clf(unix_secs: u64, out: &mut [u8; CLF_LEN]) {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);

    out[0] = b'[';
    put2(&mut out[1..3], d as u64);
    out[3] = b'/';
    out[4..7].copy_from_slice(MONTHS[(m - 1) as usize]);
    out[7] = b'/';
    put4(&mut out[8..12], y as u64);
    out[12] = b':';
    put2(&mut out[13..15], h);
    out[15] = b':';
    put2(&mut out[16..18], mi);
    out[18] = b':';
    put2(&mut out[19..21], s);
    out[21..27].copy_from_slice(b" +0000");
    out[27] = b']';
}

#[inline]
fn put2(out: &mut [u8], n: u64) {
    out[0] = b'0' + (n / 10 % 10) as u8;
    out[1] = b'0' + (n % 10) as u8;
}

#[inline]
fn put4(out: &mut [u8], n: u64) {
    out[0] = b'0' + (n / 1000 % 10) as u8;
    out[1] = b'0' + (n / 100 % 10) as u8;
    out[2] = b'0' + (n / 10 % 10) as u8;
    out[3] = b'0' + (n % 10) as u8;
}

/// Days since 1970-01-01 -> (year, month 1..=12, day 1..=31).
/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt(secs: u64) -> String {
        let mut b = [0u8; DATE_LEN];
        format_http_date(secs, &mut b);
        String::from_utf8(b.to_vec()).unwrap()
    }

    #[test]
    fn epoch() {
        assert_eq!(fmt(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn rfc_example() {
        // The example date from RFC 9110.
        assert_eq!(fmt(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    #[test]
    fn leap_day() {
        // 2024-02-29T12:00:00Z
        assert_eq!(fmt(1_709_208_000), "Thu, 29 Feb 2024 12:00:00 GMT");
    }

    #[test]
    fn clf_format() {
        let mut b = [0u8; CLF_LEN];
        format_clf(0, &mut b);
        assert_eq!(&b, b"[01/Jan/1970:00:00:00 +0000]");
        format_clf(784_111_777, &mut b);
        assert_eq!(&b, b"[06/Nov/1994:08:49:37 +0000]");
    }

    #[test]
    fn cache_returns_fixed_length() {
        let mut c = DateCache::new();
        assert_eq!(c.get().len(), DATE_LEN);
        assert!(c.get().ends_with(b" GMT"));
    }
}
