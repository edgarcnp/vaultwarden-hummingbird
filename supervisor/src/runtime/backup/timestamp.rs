//! Object-name timestamps for the backup bucket: UTC, sortable by name,
//! with a collision-proof random suffix (the full contract is on
//! [`timestamp`] itself).

use jiff::Timestamp;

/// Timestamp for object names: UTC `YYYYMMDDTHHMMSSZ` (sortable) plus a
/// random 8-hex suffix before the caller's extension — `{ts}-{rand}`.
/// Name order still equals time order (the fixed-width timestamp sorts
/// first); within the same second the two backups are interchangeable,
/// and the suffix only prevents a same-name overwrite.
pub(super) fn timestamp() -> String {
    let mut rand = [0u8; 4];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut rand)
        })
        .is_err()
    {
        // No /dev/urandom (test sandbox?): nanosecond fraction as the next
        // best uniqueness — never a hard failure, never a zero suffix.
        rand = Timestamp::now().subsec_nanosecond().to_le_bytes();
    }
    format!(
        "{}-{}",
        Timestamp::now().strftime("%Y%m%dT%H%M%SZ"),
        rand.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_is_sortable_utc_with_suffix() {
        let ts = timestamp();
        // 16-char sortable UTC stamp + '-' + 8 hex chars
        assert_eq!(ts.len(), 25);
        assert_eq!(ts.as_bytes()[16], b'-');
        assert!(ts.as_bytes()[15] == b'Z', "UTC designator at index 15");
        assert!(
            ts[17..].bytes().all(|b| b.is_ascii_hexdigit()),
            "suffix is hex"
        );
        let dt = jiff::civil::DateTime::strptime("%Y%m%dT%H%M%S", &ts[..15]).expect("round-trips");
        let parsed = dt.to_zoned(jiff::tz::TimeZone::UTC).expect("UTC");
        let drift = (parsed.timestamp().as_second() - Timestamp::now().as_second()).abs();
        assert!(drift <= 5, "timestamp drifted {drift}s from the clock");
    }

    #[test]
    fn timestamps_in_the_same_second_stay_distinct() {
        let a = timestamp();
        let b = timestamp();
        assert_ne!(a, b, "same-second backups must not collide");
        // both sort into the same second bucket
        assert_eq!(&a[..16], &b[..16]);
    }
}
