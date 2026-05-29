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
    if trimmed.as_bytes().first().copied() == Some(b'-') {
        return Err(Error::XmlParse(
            "invalid xs:dateTime: negative years not supported".to_string(),
        ));
    }

    // Locate `T` separator.
    let t_idx = trimmed
        .find('T')
        .ok_or_else(|| Error::XmlParse("invalid xs:dateTime: missing 'T' separator".to_string()))?;
    let (date_part, rest) = trimmed.split_at(t_idx);
    // Skip the 'T' (single ASCII byte, char-boundary safe).
    let time_part_with_tz = rest
        .strip_prefix('T')
        .ok_or_else(|| Error::XmlParse("invalid xs:dateTime: missing 'T' separator".to_string()))?;

    // --- Date ---
    let date_segs: Vec<&str> = date_part.split('-').collect();
    let [year_s, month_s, day_s] = date_segs.as_slice() else {
        return Err(Error::XmlParse(format!(
            "invalid xs:dateTime: bad date '{date_part}'"
        )));
    };
    let year: i32 = parse_int(year_s, "year")?;
    let month: u32 = parse_int(month_s, "month")?;
    let day: u32 = parse_int(day_s, "day")?;
    // xs:dateTime in theory permits arbitrarily large years; in SAML practice
    // they are always 4-digit CE dates. Reject anything outside [1, 9999] so
    // a malformed or attacker-supplied timestamp can never silently coerce to
    // a different point on the calendar via downstream arithmetic.
    if !(1..=9999).contains(&year) {
        return Err(Error::XmlParse(format!(
            "invalid xs:dateTime: year out of range: {year}"
        )));
    }
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
    let [hour_s, minute_s, second_s] = time_segs.as_slice() else {
        return Err(Error::XmlParse(format!(
            "invalid xs:dateTime: bad time '{time_segment}'"
        )));
    };
    let hour: u32 = parse_int(hour_s, "hour")?;
    let minute: u32 = parse_int(minute_s, "minute")?;

    // Seconds may have a fractional part.
    let (whole_sec_str, frac_nanos) = match second_s.split_once('.') {
        Some((w, f)) => (w, parse_fraction_to_nanos(f)?),
        None => (*second_s, 0u32),
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
    let days_since_epoch = days_from_civil(i64::from(year), i64::from(month), i64::from(day))
        .ok_or_else(|| {
            Error::XmlParse(format!(
                "invalid xs:dateTime: date does not exist: {year:04}-{month:02}-{day:02}"
            ))
        })?;

    let overflow = || Error::XmlParse("invalid xs:dateTime: time value out of range".to_string());
    let hour_secs = i64::from(hour).checked_mul(3600).ok_or_else(overflow)?;
    let minute_secs = i64::from(minute).checked_mul(60).ok_or_else(overflow)?;
    let seconds_in_day = hour_secs
        .checked_add(minute_secs)
        .and_then(|v| v.checked_add(i64::from(clamped_second)))
        .ok_or_else(overflow)?;
    let utc_seconds_signed = days_since_epoch
        .checked_mul(86_400)
        .and_then(|v| v.checked_add(seconds_in_day))
        .and_then(|v| v.checked_sub(offset_secs))
        .ok_or_else(overflow)?;

    if utc_seconds_signed < 0 {
        return Err(Error::XmlParse(
            "invalid xs:dateTime: pre-1970 timestamps not representable".to_string(),
        ));
    }
    let utc_seconds = u64::try_from(utc_seconds_signed).map_err(|err| {
        Error::XmlParse(format!(
            "invalid xs:dateTime: seconds value not representable: {err}"
        ))
    })?;

    UNIX_EPOCH
        .checked_add(Duration::new(utc_seconds, frac_nanos))
        .ok_or_else(overflow)
}

/// Format a `SystemTime` as an `xs:dateTime` string in UTC.
///
/// Output shape: `YYYY-MM-DDTHH:MM:SS.fffZ` (always 3 fractional digits when
/// the underlying time has sub-second precision; bare `YYYY-MM-DDTHH:MM:SSZ`
/// otherwise).
///
/// Returns `Error::XmlEmit` for `SystemTime` values whose civil representation
/// would overflow the date arithmetic. SAML timestamps in practice are many
/// orders of magnitude inside the safe range; this is a fail-closed guard
/// against caller bugs (e.g. an unchecked `now + huge_duration`) rather than a
/// real wire concern.
pub fn format_xs_datetime(t: SystemTime) -> Result<String, Error> {
    let dur = t
        .duration_since(UNIX_EPOCH)
        .map_err(|_err| Error::XmlEmit("xs:dateTime emit: pre-epoch time".to_string()))?;
    let total_secs = i64::try_from(dur.as_secs()).map_err(|_err| {
        Error::XmlEmit("xs:dateTime emit: seconds value not representable".to_string())
    })?;
    let nanos = dur.subsec_nanos();

    let days = total_secs.div_euclid(86_400);
    let sod = total_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days)?;
    // `sod` is in `[0, 86_400)` so the divisions/mods are bounded and `u32`-safe.
    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;

    Ok(if nanos == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    } else {
        // Emit millisecond precision (3 digits) which is what every major IdP
        // emits in practice. Truncate, do not round — round-tripping a parsed
        // value with sub-ms precision should not change the wire form when
        // re-emitted by something that only cares to ms.
        let millis = nanos / 1_000_000;
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
    })
}

// --- Internals ---------------------------------------------------------------

fn parse_int<T>(s: &str, field: &'static str) -> Result<T, Error>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    s.parse::<T>()
        .map_err(|err| Error::XmlParse(format!("invalid xs:dateTime: bad {field}: '{s}' ({err})")))
}

fn parse_fraction_to_nanos(frac: &str) -> Result<u32, Error> {
    if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::XmlParse(format!(
            "invalid xs:dateTime: bad fractional seconds '{frac}'"
        )));
    }
    // Truncate / right-pad to 9 digits.
    let mut buf = [b'0'; 9];
    for (slot, b) in buf.iter_mut().zip(frac.bytes()).take(9) {
        *slot = b;
    }
    let s = std::str::from_utf8(&buf).map_err(|err| {
        Error::XmlParse(format!(
            "invalid xs:dateTime: fractional seconds not utf-8 ({err})"
        ))
    })?;
    s.parse::<u32>().map_err(|err| {
        Error::XmlParse(format!(
            "invalid xs:dateTime: fractional seconds overflow ({err})"
        ))
    })
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
    if let Some(split_at) = s.len().checked_sub(6) {
        // `s` is ASCII at the relevant byte positions for any valid offset;
        // grab the candidate as a byte slice to avoid string slicing.
        let bytes = s.as_bytes();
        let candidate_bytes = bytes.get(split_at..).unwrap_or(&[]);
        let sign_byte = candidate_bytes.first().copied();
        let colon_byte = candidate_bytes.get(3).copied();
        if matches!(sign_byte, Some(b'+' | b'-')) && colon_byte == Some(b':') {
            // Pull the two-digit chunks via byte ranges, then validate ASCII.
            let hh_bytes = candidate_bytes.get(1..3).unwrap_or(&[]);
            let mm_bytes = candidate_bytes.get(4..6).unwrap_or(&[]);
            let hh_str = std::str::from_utf8(hh_bytes).map_err(|err| {
                Error::XmlParse(format!(
                    "invalid xs:dateTime: timezone hour not utf-8 ({err})"
                ))
            })?;
            let mm_str = std::str::from_utf8(mm_bytes).map_err(|err| {
                Error::XmlParse(format!(
                    "invalid xs:dateTime: timezone minute not utf-8 ({err})"
                ))
            })?;
            let hh: i64 = parse_int(hh_str, "tz-hour")?;
            let mm: i64 = parse_int(mm_str, "tz-minute")?;
            if hh > 14 || mm > 59 {
                let candidate_repr = std::str::from_utf8(candidate_bytes).unwrap_or("<non-utf8>");
                return Err(Error::XmlParse(format!(
                    "invalid xs:dateTime: bad timezone offset '{candidate_repr}'"
                )));
            }
            let overflow =
                || Error::XmlParse("invalid xs:dateTime: timezone offset out of range".to_string());
            let hh_secs = hh.checked_mul(3600).ok_or_else(overflow)?;
            let mm_secs = mm.checked_mul(60).ok_or_else(overflow)?;
            let mut offset = hh_secs.checked_add(mm_secs).ok_or_else(overflow)?;
            if sign_byte == Some(b'-') {
                offset = offset.checked_neg().ok_or_else(overflow)?;
            }
            let time_only = s.get(..split_at).ok_or_else(|| {
                Error::XmlParse(
                    "invalid xs:dateTime: malformed timezone offset boundary".to_string(),
                )
            })?;
            return Ok((time_only, offset));
        }
    }

    // No designator at all → treat as UTC.
    Ok((s, 0))
}

/// Convert civil date (y/m/d) to days since 1970-01-01, Gregorian, proleptic.
/// Algorithm from Howard Hinnant's "date" library, public domain.
/// Returns `None` if the date does not exist (e.g., Feb 30) or any
/// intermediate calculation overflows `i64`.
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    // Validate day-of-month against the actual month length.
    if !(1..=12).contains(&m) {
        return None;
    }
    let month_u32 = u32::try_from(m).ok()?;
    let max_d = i64::from(days_in_month(y, month_u32));
    if d < 1 || d > max_d {
        return None;
    }
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era_base = if y >= 0 { y } else { y.checked_sub(399)? };
    let era = era_base.checked_div(400)?;
    let yoe = y.checked_sub(era.checked_mul(400)?)?; // [0, 399]
    let m_shifted = if m > 2 {
        m.checked_sub(3)?
    } else {
        m.checked_add(9)?
    };
    let doy = 153i64
        .checked_mul(m_shifted)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(d)?
        .checked_sub(1)?; // [0, 365]
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?; // [0, 146096]
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

/// Inverse of `days_from_civil`.
///
/// Returns `Err(Error::XmlEmit)` if any intermediate computation would
/// overflow `i64`, or if the resulting year does not fit in `i32`. SAML
/// timestamps in practice are many orders of magnitude inside the safe range;
/// the fallible signature is a fail-closed guard so a corrupt or
/// pathologically-large input cannot silently coerce to a wrong date.
fn civil_from_days(z: i64) -> Result<(i32, u32, u32), Error> {
    let overflow =
        || Error::XmlEmit("xs:dateTime emit: civil date out of representable range".to_string());

    let z = z.checked_add(719_468).ok_or_else(overflow)?;
    let era_base = if z >= 0 {
        z
    } else {
        z.checked_sub(146_096).ok_or_else(overflow)?
    };
    let era = era_base.checked_div(146_097).ok_or_else(overflow)?;
    let doe = z
        .checked_sub(era.checked_mul(146_097).ok_or_else(overflow)?)
        .ok_or_else(overflow)?;
    let yoe = doe
        .checked_sub(doe.checked_div(1460).ok_or_else(overflow)?)
        .and_then(|v| v.checked_add(doe.checked_div(36_524)?))
        .and_then(|v| v.checked_sub(doe.checked_div(146_096)?))
        .and_then(|v| v.checked_div(365))
        .ok_or_else(overflow)?;
    let y_base = yoe
        .checked_add(era.checked_mul(400).ok_or_else(overflow)?)
        .ok_or_else(overflow)?;
    let leap_correction = 365i64
        .checked_mul(yoe)
        .and_then(|v| v.checked_add(yoe.checked_div(4)?))
        .and_then(|v| v.checked_sub(yoe.checked_div(100)?))
        .ok_or_else(overflow)?;
    let doy = doe.checked_sub(leap_correction).ok_or_else(overflow)?;
    let mp = 5i64
        .checked_mul(doy)
        .and_then(|v| v.checked_add(2))
        .and_then(|v| v.checked_div(153))
        .ok_or_else(overflow)?;
    let mp_term = 153i64
        .checked_mul(mp)
        .and_then(|v| v.checked_add(2))
        .and_then(|v| v.checked_div(5))
        .ok_or_else(overflow)?;
    let d_i64 = doy
        .checked_sub(mp_term)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(overflow)?;
    let m_i64 = if mp < 10 {
        mp.checked_add(3).ok_or_else(overflow)?
    } else {
        mp.checked_sub(9).ok_or_else(overflow)?
    };
    let d = u32::try_from(d_i64).map_err(|_err| overflow())?;
    let m = u32::try_from(m_i64).map_err(|_err| overflow())?;
    let y = if m <= 2 {
        y_base.checked_add(1).ok_or_else(overflow)?
    } else {
        y_base
    };
    let y_i32 = i32::try_from(y).map_err(|_err| overflow())?;
    Ok((y_i32, m, d))
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
        let s = format_xs_datetime(t).expect("format ok");
        assert_eq!(s, "2026-05-26T12:34:56Z");
    }

    #[test]
    fn parse_fractional_seconds_ms() {
        let t = parse_xs_datetime("2026-05-26T12:34:56.123Z").expect("ok");
        assert_eq!(
            format_xs_datetime(t).expect("format ok"),
            "2026-05-26T12:34:56.123Z"
        );
    }

    #[test]
    fn parse_fractional_seconds_arbitrary_precision() {
        // 7 digits → 0.1234567 s → 123_456_700 ns → emitted ms = 123
        let t = parse_xs_datetime("2026-05-26T12:34:56.1234567Z").expect("ok");
        let s = format_xs_datetime(t).expect("format ok");
        assert_eq!(s, "2026-05-26T12:34:56.123Z");
    }

    #[test]
    fn parse_positive_offset() {
        // 2026-05-26T14:34:56+02:00 == 2026-05-26T12:34:56Z
        let t = parse_xs_datetime("2026-05-26T14:34:56+02:00").expect("ok");
        assert_eq!(
            format_xs_datetime(t).expect("format ok"),
            "2026-05-26T12:34:56Z"
        );
    }

    #[test]
    fn parse_negative_offset() {
        // 2026-05-26T07:34:56-05:00 == 2026-05-26T12:34:56Z
        let t = parse_xs_datetime("2026-05-26T07:34:56-05:00").expect("ok");
        assert_eq!(
            format_xs_datetime(t).expect("format ok"),
            "2026-05-26T12:34:56Z"
        );
    }

    #[test]
    fn parse_zero_offset() {
        let t = parse_xs_datetime("2026-05-26T12:34:56+00:00").expect("ok");
        assert_eq!(
            format_xs_datetime(t).expect("format ok"),
            "2026-05-26T12:34:56Z"
        );
    }

    #[test]
    fn parse_no_offset_interpreted_as_utc() {
        let t = parse_xs_datetime("2026-05-26T12:34:56").expect("ok");
        assert_eq!(
            format_xs_datetime(t).expect("format ok"),
            "2026-05-26T12:34:56Z"
        );
    }

    #[test]
    fn round_trip_unix_epoch() {
        let t = parse_xs_datetime("1970-01-01T00:00:00Z").expect("ok");
        assert_eq!(t, UNIX_EPOCH);
        assert_eq!(
            format_xs_datetime(t).expect("format ok"),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn round_trip_leap_year_feb_29() {
        let t = parse_xs_datetime("2024-02-29T00:00:00Z").expect("ok");
        assert_eq!(
            format_xs_datetime(t).expect("format ok"),
            "2024-02-29T00:00:00Z"
        );
    }

    #[test]
    fn rejects_invalid_date() {
        parse_xs_datetime("2025-02-30T00:00:00Z").unwrap_err();
        parse_xs_datetime("2025-13-01T00:00:00Z").unwrap_err();
        parse_xs_datetime("2025-00-01T00:00:00Z").unwrap_err();
    }

    #[test]
    fn rejects_garbage() {
        parse_xs_datetime("").unwrap_err();
        parse_xs_datetime("not-a-date").unwrap_err();
        parse_xs_datetime("2025-05-26X12:00:00Z").unwrap_err();
        parse_xs_datetime("2025-05-26T25:00:00Z").unwrap_err();
    }

    #[test]
    fn rejects_pre_epoch() {
        parse_xs_datetime("1969-12-31T23:59:59Z").unwrap_err();
    }

    #[test]
    fn end_of_year_round_trip() {
        let t = parse_xs_datetime("2099-12-31T23:59:59Z").expect("ok");
        assert_eq!(
            format_xs_datetime(t).expect("format ok"),
            "2099-12-31T23:59:59Z"
        );
    }

    #[test]
    fn micro_offset_applied_to_date_boundary() {
        // 00:30 on 2026-05-27 in +01:00 is 23:30 on 2026-05-26 UTC.
        let t = parse_xs_datetime("2026-05-27T00:30:00+01:00").expect("ok");
        assert_eq!(
            format_xs_datetime(t).expect("format ok"),
            "2026-05-26T23:30:00Z"
        );
    }

    #[test]
    fn civil_from_days_unix_epoch() {
        assert_eq!(civil_from_days(0).expect("ok"), (1970, 1, 1));
    }

    #[test]
    fn civil_from_days_known_mid_range_round_trip() {
        // 2026-05-26 is `days_from_civil(2026, 5, 26)` days past 1970-01-01.
        let days = days_from_civil(2026, 5, 26).expect("date exists");
        assert_eq!(civil_from_days(days).expect("ok"), (2026, 5, 26));
    }

    #[test]
    fn civil_from_days_overflow_fails_closed() {
        // Saturating arithmetic would silently coerce this to a wrong tuple;
        // checked arithmetic must surface an error.
        civil_from_days(i64::MAX).unwrap_err();
    }

    #[test]
    fn parse_rejects_out_of_range_year() {
        // xs:dateTime in theory permits arbitrarily many year digits; for SAML
        // we reject anything outside [1, 9999] so caller-supplied input cannot
        // silently round to a wrong date via downstream arithmetic.
        parse_xs_datetime("100000-01-01T00:00:00Z").unwrap_err();
    }
}
