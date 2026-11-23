//! Dates of the language. Always UTC: `2026-01-01` or `2026-01-01T09:00:00Z`, optionally with
//! milliseconds (`...:00.250Z`). The result is milliseconds since the Unix epoch, as in the grants.

const MS_PER_SECOND: i64 = 1_000;
const MS_PER_DAY: i64 = 86_400_000;
const EPOCH_YEAR: i64 = 1970;

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn digits(text: &str) -> Option<i64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Reads a date. The error says what is wrong in words fit for a diagnostic.
pub(crate) fn parse(text: &str) -> Result<u64, String> {
    let bad = || "use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ".to_string();
    let (date, time) = match text.split_once('T') {
        Some((date, time)) => (date, Some(time)),
        None => (text, None),
    };
    let mut parts = date.split('-');
    let (Some(y), Some(m), Some(d), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(bad());
    };
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return Err(bad());
    }
    let (Some(year), Some(month), Some(day)) = (digits(y), digits(m), digits(d)) else {
        return Err(bad());
    };
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return Err("impossible calendar date".to_string());
    }
    if year < EPOCH_YEAR {
        return Err("dates before 1970-01-01 cannot be represented".to_string());
    }
    let mut ms = days_from_civil(year, month, day) * MS_PER_DAY;
    if let Some(time) = time {
        let Some(clock) = time.strip_suffix('Z') else {
            return Err(
                "time without zone; dates are UTC, so add a trailing Z (for example 2026-01-01T09:00:00Z)".into(),
            );
        };
        let (clock, fraction) = match clock.split_once('.') {
            Some((clock, fraction)) => (clock, Some(fraction)),
            None => (clock, None),
        };
        let fields: Vec<&str> = clock.split(':').collect();
        let (hours, minutes, seconds) = match fields.as_slice() {
            [h, m] => (*h, *m, "00"),
            [h, m, s] => (*h, *m, *s),
            _ => return Err(bad()),
        };
        if [hours, minutes, seconds].iter().any(|f| f.len() != 2) {
            return Err(bad());
        }
        let (Some(h), Some(mi), Some(s)) = (digits(hours), digits(minutes), digits(seconds)) else {
            return Err(bad());
        };
        if h > 23 || mi > 59 || s > 59 {
            return Err("impossible time of day".to_string());
        }
        let millis = match fraction {
            None => 0,
            Some(f) if (1..=3).contains(&f.len()) => digits(f).ok_or_else(bad)? * 10_i64.pow(3 - f.len() as u32),
            Some(_) => return Err("fractions of a second go up to milliseconds (three digits)".to_string()),
        };
        ms += (h * 3_600 + mi * 60 + s) * MS_PER_SECOND + millis;
    }
    u64::try_from(ms).map_err(|_| "dates before 1970-01-01 cannot be represented".to_string())
}

/// The last instant the language can write: the end of the year 9999 (dates have four digits).
const MAX_MS: i64 = 253_402_300_799_999;

/// Writes a date the way the language reads it: a bare date at midnight, else date and time in UTC.
/// `None` for an instant past the year 9999, which the language has no spelling for.
pub(crate) fn format(ms: u64) -> Option<String> {
    let ms = i64::try_from(ms).ok().filter(|ms| *ms <= MAX_MS)?;
    let (days, rest) = (ms.div_euclid(MS_PER_DAY), ms.rem_euclid(MS_PER_DAY));
    let (year, month, day) = civil_from_days(days);
    if rest == 0 {
        return Some(format!("{year:04}-{month:02}-{day:02}"));
    }
    let (secs, millis) = (rest / MS_PER_SECOND, rest % MS_PER_SECOND);
    let (h, mi, s) = (secs / 3_600, secs % 3_600 / 60, secs % 60);
    let fraction = if millis == 0 {
        String::new()
    } else {
        format!(".{millis:03}")
    };
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{h:02}:{mi:02}:{s:02}{fraction}Z"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_dates_and_instants_in_utc() {
        assert_eq!(parse("1970-01-01"), Ok(0));
        assert_eq!(parse("2026-01-01"), Ok(1_767_225_600_000));
        assert_eq!(parse("2026-01-01T09:00:00Z"), Ok(1_767_225_600_000 + 9 * 3_600_000));
        assert_eq!(parse("2026-01-01T09:00Z"), parse("2026-01-01T09:00:00Z"));
        assert_eq!(parse("2026-01-01T00:00:00.250Z"), Ok(1_767_225_600_250));
    }

    #[test]
    fn refuses_what_is_not_utc_or_not_real() {
        assert!(parse("2026-01-01T09:00:00").unwrap_err().contains("trailing Z"));
        assert!(parse("2026-02-30").unwrap_err().contains("impossible"));
        assert!(parse("2025-02-29").is_err() && parse("2024-02-29").is_ok());
        assert!(parse("2026-01-01T24:00:00Z").is_err());
        assert!(parse("1969-12-31").unwrap_err().contains("1970"));
    }

    #[test]
    fn refuses_to_write_what_has_no_spelling() {
        assert_eq!(format(253_402_300_799_999).as_deref(), Some("9999-12-31T23:59:59.999Z"));
        assert_eq!(format(253_402_300_800_000), None);
        assert_eq!(format(u64::MAX), None);
    }

    #[test]
    fn formats_back_what_it_reads() {
        for text in [
            "1970-01-01",
            "2026-01-01",
            "2026-12-31T23:59:59Z",
            "2028-02-29T01:02:03.004Z",
        ] {
            assert_eq!(format(parse(text).unwrap()).as_deref(), Some(text));
        }
    }
}
