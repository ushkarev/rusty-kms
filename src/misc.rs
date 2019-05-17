use base64::{decode as b64decode, encode as b64encode};
use chrono::{DateTime, TimeZone, Utc};
use regex::Regex;

lazy_static! {
    static ref RE_ALIAS: Regex = Regex::new(r"^[a-zA-Z0-9:/_-]+$").expect("cannot compile regex");
    static ref RE_TAG: Regex = Regex::new(r"^[\w\d\s+=.:/_-]+$").expect("cannot compile regex");  // TODO: unused
}

#[inline]
pub fn is_valid_alias(alias: &str) -> bool {
    let alias_len = alias.len();
    alias_len > 0 && alias_len <= 256 &&
        alias.starts_with("alias/") &&
        !alias.starts_with("alias/aws/") &&
        RE_ALIAS.is_match(alias)
}

#[inline]
pub fn is_valid_tag(key: &str, value: &str) -> bool {
    // TODO: use RE_TAG?
    let key_len = key.len();
    let value_len = value.len();
    key_len > 0 && key_len <= 128 && value_len > 0 && value_len <= 256 &&
        !key.starts_with("aws:") && !value.starts_with("aws:")
}

const NANOS_PER_SEC: f64 = 1_000_000_000f64;

#[inline]
pub fn timestamp_to_datetime(n: f64) -> Option<DateTime<Utc>> {
    let s = n.trunc();
    let ns = n.fract() * NANOS_PER_SEC;
    Utc.timestamp_opt(s as i64, ns as u32).single()
}

#[inline]
pub fn datetime_to_timestamp(datetime: &DateTime<Utc>) -> f64 {
    let s = datetime.timestamp() as f64;
    s + f64::from(datetime.timestamp_subsec_nanos()) / NANOS_PER_SEC
}

pub fn page_from_marker(marker: &str) -> Result<usize, ()> {
    b64decode(marker)
        .map_err(|_| ())
        .and_then(|marker| {
            if marker.len() == 4 {
                // only supports 64 bit usize
                Ok(
                    (marker[0] as usize) +
                    ((marker[1] as usize) << 8) +
                    ((marker[2] as usize) << 16) +
                    ((marker[3] as usize) << 24)
                )
            } else {
                Err(())
            }
        })
}

pub fn marker_from_page(page: usize) -> String {
    // only supports 64 bit usize
    assert_eq!(std::mem::size_of::<usize>(), 8);
    let page_bytes = [
        (page & 0xff) as u8,
        (page >> 8 & 0xff) as u8,
        (page >> 16 & 0xff) as u8,
        (page >> 24 & 0xff) as u8,
    ];
    b64encode(&page_bytes)
}

pub fn paginate<T>(items: &mut Vec<T>, current_page: usize, per_page: usize) -> Result<String, ()> {
    let blank = String::new();
    let len = items.len();
    if len == 0 {
        return Ok(blank);
    }
    if current_page * per_page >= len {
        return Err(());
    }
    if current_page > 0 {
        items.drain(0..current_page * per_page);
    }
    if items.len() > per_page {
        items.drain(per_page..);
        Ok(marker_from_page(current_page + 1))
    } else {
        Ok(blank)
    }
}
