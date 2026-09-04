use chrono::{DateTime, TimeZone, Utc};

const FILETIME_EPOCH_DELTA: i128 = 116_444_736_000_000_000;

pub fn filetime(value: u64) -> Option<DateTime<Utc>> {
    if value == 0 {
        return None;
    }
    let ticks = i128::from(value) - FILETIME_EPOCH_DELTA;
    let seconds = ticks.div_euclid(10_000_000);
    let nanos = ticks.rem_euclid(10_000_000) * 100;
    let seconds = i64::try_from(seconds).ok()?;
    Utc.timestamp_opt(seconds, nanos as u32).single()
}

pub fn forensic(value: Option<DateTime<Utc>>) -> Option<String> {
    value.map(|v| v.format("%Y-%m-%d %H:%M:%S%.6f UTC").to_string())
}

pub fn now() -> String {
    forensic(Some(Utc::now())).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn converts_windows_epoch() {
        assert_eq!(filetime(116_444_736_000_000_000).unwrap().timestamp(), 0);
    }
}
