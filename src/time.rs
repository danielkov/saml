//! XML Schema `xs:dateTime` parsing and emission.
//!
//! SAML wire timestamps are `xs:dateTime`. We accept the practical subset that
//! actually appears in production IdP responses:
//!
//! - `YYYY-MM-DDTHH:MM:SS[.fff…][Z|±HH:MM]`
//! - Trailing `Z` means UTC.
//! - `±HH:MM` offset is honored.
//! - Absence of any timezone designator is interpreted as UTC (the spec calls
//!   this "unspecified"; SAML deployments universally mean UTC).
//! - Fractional seconds are accepted at any precision and truncated to
//!   nanoseconds.
//!
//! Errors are reported as `Error::XmlParse(String)`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::Error;

/// Parse an `xs:dateTime` string into a `SystemTime`.
pub fn parse_xs_datetime(s: &str) -> Result<SystemTime, Error> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(Error::XmlParse(
            "invalid xs:dateTime: empty string".to_string(),
        ));
    }

    // Date portion: optional leading `-` (BCE) is rejected — SAML timestamps
    // are always CE — so we require a positive year. The date and time are
    // separated by `T`.
    let bytes = trimmed.as_bytes();
    if bytes[0] == b'-' {
        return Err(Error::XmlParse(
            "invalid xs:dateTime: negative years not supported".to_string(),
        ));
    }

    // Locate `T` separator.
    let t_idx = trimmed
        .find('T')
        .ok_or_else(|| Error::XmlParse("invalid xs:dateTime: missing 'T' separator".to_string()))?;
    let (date_part, rest) = trimmed.split_at(t_idx);
    let time_part_with_tz = &rest[1..]; // skip 'T'

    // --- Date ---
    let date_segs: Vec<&str> = date_part.split('-').collect();
    if date_segs.len() != 3 {
        return Err(Error::XmlParse(format!(
            "invalid xs:dateTime: bad date '{date_part}'"
        )));
    }
    let year: i32 = parse_int(date_segs[0], "year")?;
    let month: u32 = parse_int(date_segs[1], "month")?;
    let day: u32 = parse_int(date_segs[2], "day")?;
    if !(1..=12).contains(&month) {
        return Err(Error::XmlParse(format!(
            "invalid xs:dateTime: month out of range: {month}"
        )));
    }
    if !(1..=31).contains(&day) {
        return Err(Error::XmlParse(format!(
            "invalid xs:dateTime: day out of range: {day}"
        )));
    }

    // --- Timezone split ---
    // The TZ designator is either trailing 'Z', or '+HH:MM' / '-HH:MM' offset.
    // We must NOT confuse the '-' inside an offset with anything else: the date
    // has been peeled off, so any '+' or trailing '-HH:MM' here is the offset.
    let (time_segment, offset_secs) = split_offset(time_part_with_tz)?;

    // --- Time ---
    let time_segs: Vec<&str> = time_segment.split(':').collect();
    if time_segs.len() != 3 {
        return Err(Error::XmlParse(format!(
            "invalid xs:dateTime: bad time '{time_segment}'"
        )));
    }
    let hour: u32 = parse_int(time_segs[0], "hour")?;
    let minute: u32 = parse_int(time_segs[1], "minute")?;

    // Seconds may have a fractional part.
    let (whole_sec_str, frac_nanos) = match time_segs[2].split_once('.') {
        Some((w, f)) => (w, parse_fraction_to_nanos(f)?),
        None => (time_segs[2], 0u32),
    };
    let second: u32 = parse_int(whole_sec_str, "second")?;

    if hour > 23 {
        return Err(Error::XmlParse(format!(
            "invalid xs:dateTime: hour out of range: {hour}"
        )));
    }
    if minute > 59 {
        return Err(Error::XmlParse(format!(
            "invalid xs:dateTime: minute out of range: {minute}"
        )));
    }
    // xs:dateTime allows 60 for leap second; we treat as 59 for SystemTime
    // arithmetic (the resulting absolute instant is within one second, which
    // is well inside SAML clock-skew tolerances).
    let clamped_second = second.min(59);
    if second > 60 {
        return Err(Error::XmlParse(format!(
            "invalid xs:dateTime: second out of range: {second}"
        )));
    }

    // --- Convert civil time to Unix seconds (UTC) ---
    let days_since_epoch =
        days_from_civil(year as i64, month as i64, day as i64).ok_or_else(|| {
            Error::XmlParse(format!(
                "invalid xs:dateTime: date does not exist: {year:04}-{month:02}-{day:02}"
            ))
        })?;

    let seconds_in_day =
        (hour as i64) * 3600 + (minute as i64) * 60 + (clamped_second as i64);
    let utc_seconds_signed = days_since_epoch * 86_400 + seconds_in_day - offset_secs;

    if utc_seconds_signed < 0 {
        return Err(Error::XmlParse(
            "invalid xs:dateTime: pre-1970 timestamps not representable".to_string(),
        ));
    }
    let utc_seconds = utc_seconds_signed as u64;

    Ok(UNIX_EPOCH + Duration::new(utc_seconds, frac_nanos))
}

/// Format a `SystemTime` as an `xs:dateTime` string in UTC.
///
/// Output shape: `YYYY-MM-DDTHH:MM:SS.fffZ` (always 3 fractional digits when
/// the underlying time has sub-second precision; bare `YYYY-MM-DDTHH:MM:SSZ`
/// otherwise).
pub fn format_xs_datetime(t: SystemTime) -> String {
    let dur = t
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::ZERO);
    let total_secs = dur.as_secs() as i64;
    let nanos = dur.subsec_nanos();

    let days = total_secs.div_euclid(86_400);
    let sod = total_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;

    if nanos == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    } else {
        // Emit millisecond precision (3 digits) which is what every major IdP
        // emits in practice. Truncate, do not round — round-tripping a parsed
        // value with sub-ms precision should not change the wire form when
        // re-emitted by something that only cares to ms.
        let millis = nanos / 1_000_000;
        format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
        )
    }
}

// --- Internals ---------------------------------------------------------------

fn parse_int<T>(s: &str, field: &'static str) -> Result<T, Error>
where
    T: std::str::FromStr,
{
    s.parse::<T>()
        .map_err(|_| Error::XmlParse(format!("invalid xs:dateTime: bad {field}: '{s}'")))
}

fn parse_fraction_to_nanos(frac: &str) -> Result<u32, Error> {
    if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::XmlParse(format!(
            "invalid xs:dateTime: bad fractional seconds '{frac}'"
        )));
    }
    // Truncate / right-pad to 9 digits.
    let mut buf = [b'0'; 9];
    for (i, b) in frac.bytes().take(9).enumerate() {
        buf[i] = b;
    }
    let s = std::str::from_utf8(&buf).expect("ascii digits");
    s.parse::<u32>()
        .map_err(|_| Error::XmlParse("invalid xs:dateTime: fractional seconds overflow".into()))
}

/// Split the `HH:MM:SS[.fff]` portion from the trailing offset designator.
/// Returns the time portion plus the offset in seconds east of UTC.
fn split_offset(s: &str) -> Result<(&str, i64), Error> {
    if let Some(stripped) = s.strip_suffix('Z') {
        return Ok((stripped, 0));
    }

    // An explicit offset is `±HH:MM`. Scan from the right.
    // Locate the offset sign: the last '+' or '-' in the string AFTER the
    // last ':' that belongs to the time portion is ambiguous; instead, look
    // for a `+` or `-` followed by exactly `HH:MM`.
    if s.len() >= 6 {
        let candidate = &s[s.len() - 6..];
        let sign_byte = candidate.as_bytes()[0];
        if (sign_byte == b'+' || sign_byte == b'-') && candidate.as_bytes()[3] == b':' {
            let hh: i64 = parse_int(&candidate[1..3], "tz-hour")?;
            let mm: i64 = parse_int(&candidate[4..6], "tz-minute")?;
            if hh > 14 || mm > 59 {
                return Err(Error::XmlParse(format!(
                    "invalid xs:dateTime: bad timezone offset '{candidate}'"
                )));
            }
            let mut offset = hh * 3600 + mm * 60;
            if sign_byte == b'-' {
                offset = -offset;
            }
            return Ok((&s[..s.len() - 6], offset));
        }
    }

    // No designator at all → treat as UTC.
    Ok((s, 0))
}

/// Convert civil date (y/m/d) to days since 1970-01-01, Gregorian, proleptic.
/// Algorithm from Howard Hinnant's "date" library, public domain.
/// Returns `None` if the date does not exist (e.g., Feb 30).
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    // Validate day-of-month against the actual month length.
    if !(1..=12).contains(&m) {
        return None;
    }
    let max_d = days_in_month(y, m as u32) as i64;
    if d < 1 || d > max_d {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    Some(era * 146_097 + doe - 719_468)
}

/// Inverse of `days_from_civil`.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as i64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// --- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_utc_z() {
        let t = parse_xs_datetime("2026-05-26T12:34:56Z").expect("ok");
        let s = format_xs_datetime(t);
        assert_eq!(s, "2026-05-26T12:34:56Z");
    }

    #[test]
    fn parse_fractional_seconds_ms() {
        let t = parse_xs_datetime("2026-05-26T12:34:56.123Z").expect("ok");
        assert_eq!(format_xs_datetime(t), "2026-05-26T12:34:56.123Z");
    }

    #[test]
    fn parse_fractional_seconds_arbitrary_precision() {
        // 7 digits → 0.1234567 s → 123_456_700 ns → emitted ms = 123
        let t = parse_xs_datetime("2026-05-26T12:34:56.1234567Z").expect("ok");
        let s = format_xs_datetime(t);
        assert_eq!(s, "2026-05-26T12:34:56.123Z");
    }

    #[test]
    fn parse_positive_offset() {
        // 2026-05-26T14:34:56+02:00 == 2026-05-26T12:34:56Z
        let t = parse_xs_datetime("2026-05-26T14:34:56+02:00").expect("ok");
        assert_eq!(format_xs_datetime(t), "2026-05-26T12:34:56Z");
    }

    #[test]
    fn parse_negative_offset() {
        // 2026-05-26T07:34:56-05:00 == 2026-05-26T12:34:56Z
        let t = parse_xs_datetime("2026-05-26T07:34:56-05:00").expect("ok");
        assert_eq!(format_xs_datetime(t), "2026-05-26T12:34:56Z");
    }

    #[test]
    fn parse_zero_offset() {
        let t = parse_xs_datetime("2026-05-26T12:34:56+00:00").expect("ok");
        assert_eq!(format_xs_datetime(t), "2026-05-26T12:34:56Z");
    }

    #[test]
    fn parse_no_offset_interpreted_as_utc() {
        let t = parse_xs_datetime("2026-05-26T12:34:56").expect("ok");
        assert_eq!(format_xs_datetime(t), "2026-05-26T12:34:56Z");
    }

    #[test]
    fn round_trip_unix_epoch() {
        let t = parse_xs_datetime("1970-01-01T00:00:00Z").expect("ok");
        assert_eq!(t, UNIX_EPOCH);
        assert_eq!(format_xs_datetime(t), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn round_trip_leap_year_feb_29() {
        let t = parse_xs_datetime("2024-02-29T00:00:00Z").expect("ok");
        assert_eq!(format_xs_datetime(t), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn rejects_invalid_date() {
        assert!(parse_xs_datetime("2025-02-30T00:00:00Z").is_err());
        assert!(parse_xs_datetime("2025-13-01T00:00:00Z").is_err());
        assert!(parse_xs_datetime("2025-00-01T00:00:00Z").is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_xs_datetime("").is_err());
        assert!(parse_xs_datetime("not-a-date").is_err());
        assert!(parse_xs_datetime("2025-05-26X12:00:00Z").is_err());
        assert!(parse_xs_datetime("2025-05-26T25:00:00Z").is_err());
    }

    #[test]
    fn rejects_pre_epoch() {
        assert!(parse_xs_datetime("1969-12-31T23:59:59Z").is_err());
    }

    #[test]
    fn end_of_year_round_trip() {
        let t = parse_xs_datetime("2099-12-31T23:59:59Z").expect("ok");
        assert_eq!(format_xs_datetime(t), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn micro_offset_applied_to_date_boundary() {
        // 00:30 on 2026-05-27 in +01:00 is 23:30 on 2026-05-26 UTC.
        let t = parse_xs_datetime("2026-05-27T00:30:00+01:00").expect("ok");
        assert_eq!(format_xs_datetime(t), "2026-05-26T23:30:00Z");
    }
}
