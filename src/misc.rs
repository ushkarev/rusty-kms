use std::io::Error as IoError;

use chrono::{DateTime, TimeZone, Utc};
use time::Duration as OldDuration;

use crate::key_store::{KeyMaterial, derive_key_material};

pub fn get_password_from_tty() -> Result<KeyMaterial, IoError> {
    let password = rpassword::read_password_from_tty(Some("Key store password: "))?;
    Ok(derive_key_material(&password))
}

#[inline(always)]
pub fn days_from_now(days: i64) -> DateTime<Utc> {
    Utc::now() + OldDuration::days(days)
}

const NANOS_PER_SEC: f64 = 1_000_000_000f64;

#[inline]
pub fn timestamp_to_datetime(timestamp: f64) -> Option<DateTime<Utc>> {
    let s = timestamp.trunc();
    let ns = timestamp.fract() * NANOS_PER_SEC;
    Utc.timestamp_opt(s as i64, ns as u32).single()
}

#[inline]
pub fn datetime_to_timestamp(datetime: &DateTime<Utc>) -> f64 {
    let s = datetime.timestamp() as f64;
    s + f64::from(datetime.timestamp_subsec_nanos()) / NANOS_PER_SEC
}
