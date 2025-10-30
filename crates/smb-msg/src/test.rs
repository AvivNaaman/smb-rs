//! This module is only used when testing the library.
//! Any `pub use` here is also imported in the [super] module.
//! It may only be used inside tests.

use super::*;
use binrw::prelude::*;
use std::io::Cursor;

/// Implementation of reading plain content test
macro_rules! _test_generic_read {
    (
        $req_or_resp:ident => $test_name:ident, $command:expr => $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        pastey::paste! {
            #[test]
            fn [<test_content_  $req_or_resp:lower _ $test_name:snake _read>]() {
                use ::binrw::{io::Cursor, prelude::*};
                let hex_bytes = ::smb_tests::hex_to_u8_array! { $hex };
                let mut cursor = Cursor::new(hex_bytes);
                let msg: [<Plain $req_or_resp:camel>] = cursor.read_le().unwrap();
                let msg: [<$struct_name $req_or_resp:camel>] = msg.content.[<to_ $struct_name:lower>]().unwrap();
                assert_eq!(msg, [<$struct_name $req_or_resp:camel>] {
                    $(
                        $field_name: $field_value,
                    )*
                });
            }
        }
    };
}

/// Implementation of writing plain content test
macro_rules! _test_generic_write {
    (
        $req_or_resp:ident => $test_name:ident, $command:expr => $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        pastey::paste! {
            #[test]
            fn [<test_content_ $req_or_resp:lower _ $test_name:snake _write>]() {
                use ::binrw::{io::Cursor, prelude::*};
                let response = [<$struct_name $req_or_resp:camel>] {
                    $(
                        $field_name: $field_value,
                    )*
                };
                let mut cursor = Cursor::new(Vec::new());
                let mut msg = [<Plain $req_or_resp:camel>]::new_with_command(response.into(), $command);

                if stringify!([<$req_or_resp:lower>]) == "response" {
                    msg.header.flags.set_server_to_redir(true); // Since we're writing a response, we must set this flag
                }

                msg.write(&mut cursor).unwrap();
                let written_bytes = cursor.into_inner();
                let expected_bytes = ::smb_tests::hex_to_u8_array! { $hex };
                assert_eq!(&written_bytes[Header::STRUCT_SIZE..], &expected_bytes[Header::STRUCT_SIZE..]);
            }
        }
    }
}

/// This macro calls other macros to implement both read and write tests
/// It has all the variants of test macros in this module, eventually calling `$impl_macro`.
macro_rules! _test_generic_impl {
    (
        $impl_macro:ident, $req_or_resp:ident => $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        _test_generic_impl! {
            $impl_macro, $req_or_resp =>
            $struct_name: $struct_name {
                $($field_name : $field_value),*
            } => $hex
        }
    };
    (
        $impl_macro:ident, $req_or_resp:ident => $test_name:ident: $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        _test_generic_impl! {
            $impl_macro, $req_or_resp =>
            $test_name, Command::$struct_name => $struct_name {
                $($field_name : $field_value),*
            } => $hex
        }
    };
    (
        $impl_macro:ident, $($v:tt)+
    ) => {
        $impl_macro! {
            $($v)+
        }
    };
}

/// Internal macro, do not use directly. See [test_request] and [test_response].
///
/// - This macro expands to test impl for read and write,
/// through [`_test_generic_impl`] using [`_test_generic_read`] and [`_test_generic_write`].
macro_rules! _test_read_write_generic {
    (
        $req_or_resp:ident => $($v:tt)+
    ) => {
        _test_generic_impl! {
            _test_generic_write, $req_or_resp => $($v)*
        }
        _test_generic_impl! {
            _test_generic_read, $req_or_resp => $($v)*
        }
    }
}

pub(crate) use _test_generic_impl;
pub(crate) use _test_generic_read;
pub(crate) use _test_generic_write;
pub(crate) use _test_read_write_generic;

macro_rules! test_request {
    ($($v:tt)+) => {
        _test_read_write_generic! {
            Request => $($v)+
        }
    };
}

macro_rules! test_response {
    ($($v:tt)+) => {
        _test_read_write_generic! {
            Response => $($v)+
        }
    };
}

macro_rules! test_request_read {
    ($($v:tt)+) => {
        _test_generic_impl! {
            _test_generic_read, Request => $($v)*
        }
    };
}

macro_rules! test_response_read {
    ($($v:tt)+) => {
        _test_generic_impl! {
            _test_generic_read, Response => $($v)*
        }
    };
}

macro_rules! test_request_write {
    ($($v:tt)+) => {
        _test_generic_impl! {
            _test_generic_write, Request => $($v)*
        }
    };
}

macro_rules! test_response_write {
    ($($v:tt)+) => {
        _test_generic_impl! {
            _test_generic_write, Response => $($v)*
        }
    };
}

pub(crate) use test_request;
pub(crate) use test_request_read;
pub(crate) use test_request_write;
pub(crate) use test_response;
pub(crate) use test_response_read;
pub(crate) use test_response_write;
