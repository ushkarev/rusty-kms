use std::convert::TryInto;
use std::str::FromStr;

use base64::{decode_config as b64decode, encode_config as b64encode, STANDARD_NO_PAD};

pub fn paginate<T>(items: &mut Vec<T>, current_page: usize, per_page: usize) -> Result<Option<Marker>, ()> {
    if per_page == 0 {
        return Err(());
    }
    let len = items.len();
    if current_page == 0 && len == 0 {
        return Ok(None);
    }
    if current_page * per_page >= len {
        return Err(());
    }
    if current_page > 0 {
        items.drain(0..current_page * per_page);
    }
    if items.len() > per_page {
        items.drain(per_page..);
        Ok(Some(Marker::new(current_page + 1)))
    } else {
        Ok(None)
    }
}

#[derive(Debug)]
pub struct Marker {
    page: usize,
    // TODO: add some sort of mutation flag? e.g. vec len or edit count?
}

impl Marker {
    #[inline]
    pub fn new(page: usize) -> Marker {
        Marker { page }
    }

    #[inline]
    pub fn page(&self) -> usize {
        self.page
    }

    pub fn to_string(&self) -> String {
        b64encode(&self.page.to_be_bytes(), STANDARD_NO_PAD)
    }
}

impl FromStr for Marker {
    type Err = ();

    fn from_str(marker: &str) -> Result<Self, Self::Err> {
        b64decode(marker, STANDARD_NO_PAD)
            .or(Err(()))
            .and_then(|marker| {
                let page_bytes: [u8; 8] = marker.as_slice().try_into()
                    .or(Err(()))?;
                let page = usize::from_be_bytes(page_bytes);
                Ok(Marker { page })
            })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages() {
        let mut list = vec![0, 1, 2, 3, 4];
        let result = paginate(&mut list, 0, 2);
        assert!(result.is_ok(), "{:?}", result);
        assert_eq!(list, vec![0, 1]);
        assert_eq!(result.unwrap().map(|marker| marker.page()), Some(1));

        let mut list = vec![0, 1, 2, 3, 4];
        let result = paginate(&mut list, 2, 2);
        assert!(result.is_ok(), "{:?}", result);
        assert_eq!(list, vec![4]);
        assert_eq!(result.unwrap().map(|marker| marker.page()), None);

        let mut list = vec![0, 1, 2, 3, 4];
        assert!(paginate(&mut list, 3, 2).is_err());
    }
}
