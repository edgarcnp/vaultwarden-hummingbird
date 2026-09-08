//! Object-name timestamps for the backup bucket: UTC, sortable by name.

/// Timestamp for object names: UTC, `YYYYMMDDTHHMMSSZ` (sortable).
pub(super) fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let days = now.as_secs() / 86_400;
    let secs_of_day = now.as_secs() % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        secs_of_day / 3600,
        secs_of_day % 3600 / 60,
        secs_of_day % 60
    )
}

/// Days-since-epoch to (year, month, day) — Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
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

    #[test]
    fn timestamp_is_sortable_utc() {
        let ts = timestamp();
        assert_eq!(ts.len(), 16);
        assert!(ts.ends_with('Z'));
        assert!(ts.chars().take(15).all(|c| c.is_ascii_digit() || c == 'T'));
    }

    #[test]
    fn civil_epoch_and_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // verified: 2026-09-08 - 1970-01-01 = 20704 days
        assert_eq!(civil_from_days(20_704), (2026, 9, 8));
        // leap-day inclusive: 2000-02-29 is day 11016
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }
}
