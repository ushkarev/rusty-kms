use crate::authorisation::{Authorisation, Access};
use crate::key_store::lookup::Lookup;
use crate::key_store::key::Key;
use crate::key_store::store::{Store, KeyIterator, AliasIterator};

impl Store {
    pub fn authorised_keys<'i, 'a, A>(&'i self, authorisation: &'a A) -> AuthorisedKeyIterator<'i, 'a, A> where 'a: 'i, A: Authorisation {
        AuthorisedKeyIterator { iter: self.iter(), authorisation }
    }

    pub fn authorised_aliases<'i, 'a, A>(&'i self, authorisation: &'a A) -> AuthorisedAliasIterator<'i, 'a, A> where 'a: 'i, A: Authorisation {
        AuthorisedAliasIterator { iter: self.iter_aliases(), authorisation }
    }

    pub fn authorised_get<A>(&self, authorisation: &A, access: Access, lookup: Lookup) -> Option<&Key> where A: Authorisation {
        self.get_by_lookup(lookup)
            .and_then(|key| if authorisation.authorises_access(key, access).is_ok() {
                Some(key)
            } else {
                None
            })
    }

    pub fn authorised_get_mut<A>(&mut self, authorisation: &A, access: Access, lookup: Lookup) -> Option<&mut Key> where A: Authorisation {
        self.get_by_lookup_mut(lookup)
            .and_then(|key| if authorisation.authorises_access(key, access).is_ok() {
                Some(key)
            } else {
                None
            })
    }
}

pub struct AuthorisedKeyIterator<'i, 'a, A> where 'a: 'i, A: Authorisation {
    iter: KeyIterator<'i>,
    authorisation: &'a A,
}

impl<'i, 'a, A> Iterator for AuthorisedKeyIterator<'i, 'a, A> where 'a: 'i, A: Authorisation {
    type Item = &'i Key;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.iter.next() {
                Some(key) => {
                    if self.authorisation.authorises_access(key, Access::Default).is_ok() {
                        return Some(key);
                    }
                },
                None => return None,
            }
        }
    }
}

pub struct AuthorisedAliasIterator<'i, 'a, A> where 'a: 'i, A: Authorisation {
    iter: AliasIterator<'i>,
    authorisation: &'a A,
}

impl<'i, 'a, A> Iterator for AuthorisedAliasIterator<'i, 'a, A> where 'a: 'i, A: Authorisation {
    type Item = (&'i str, &'i Key);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.iter.next() {
                Some((alias_arn, key)) => {
                    if self.authorisation.authorises_access(key, Access::Default).is_ok() {
                        return Some((alias_arn, key));
                    }
                },
                None => return None,
            }
        }
    }
}
