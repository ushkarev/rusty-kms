#![deny(unused_must_use)]

#![feature(test)]
extern crate test;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

#[macro_export]
macro_rules! define_error {
    ( $Error:ident = $description:expr ) => {
        #[derive(Debug, PartialEq, Eq)]
        pub struct $Error;

        impl std::error::Error for $Error {}

        impl std::fmt::Display for $Error {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "invalid state")
            }
        }
    };

    ( $Error:ident; $( $Option:ident = $description:expr ),+ ) => {
        #[derive(Debug, PartialEq, Eq)]
        pub enum $Error {
            $(
            $Option,
            )*
        }

        impl std::error::Error for $Error {}

        impl std::fmt::Display for $Error {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match self {
                    $(
                        $Error::$Option => write!(f, $description),
                    )*
                }
            }
        }
    };
}

pub mod misc;
#[macro_use]
pub mod authorisation;
#[macro_use]
pub mod key_store;
pub mod requests;
