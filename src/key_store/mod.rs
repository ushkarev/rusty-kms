pub mod errors;
mod alias;
mod tag;
mod crypto;
mod wrapping;
mod import_token;
mod key;
mod store;
mod lookup;

pub use crypto::{KeyMaterial, derive_key_material};
pub use lookup::Lookup;
pub use alias::{AliasArn, AliasName};
pub use key::{Key, KeyArn};
pub use tag::Tag;
pub use wrapping::WrappedCipherText;
pub use import_token::{ImportToken, ImportMode, import_key_public_data, private_decrypt};
pub use store::{Store, PortableStore};

/*
cipher text shape:
[ encrypted structure: [u8;?] | tag: [u8;16] ] | nonce: [u8;12] | arn [u8;?] | arn length: u8 | key generation: u8 | version: u8 ]
[                       data needed for encryption/decryption < | > public wrapper needed to find key                            ]

TODO: can nonce be publicly visible?
TODO: may be worth putting public wrapper at the beginning to use `in_prefix_len` of `open_in_place()`
TODO: arn is clearly visible in cipher text... should the whole thing be encrypted with IMPORT_KEY?
*/
