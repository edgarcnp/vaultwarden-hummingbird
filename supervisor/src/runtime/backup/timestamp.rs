//! Object-name timestamps for the backup bucket: UTC, sortable by name.

use jiff::Timestamp;

/// Timestamp for object names: UTC, `YYYYMMDDTHHMMSSZ` (sortable).
pub(super) fn timestamp() -> String {
    Timestamp::now().strftime("%Y%m%dT%H%M%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The format is load-bearing: object names must sort by creation
    /// time, and the value must round-trip through the same format.
    #[test]
    fn timestamp_is_sortable_utc() {
        let ts = timestamp();
        assert_eq!(ts.len(), 16);
        assert!(ts.ends_with('Z'));
        let dt = jiff::civil::DateTime::strptime("%Y%m%dT%H%M%S", &ts[..15]).expect("round-trips");
        let parsed = dt.to_zoned(jiff::tz::TimeZone::UTC).expect("UTC");
        let drift = (parsed.timestamp().as_second() - Timestamp::now().as_second()).abs();
        assert!(drift <= 5, "timestamp drifted {drift}s from the clock");
    }
}
