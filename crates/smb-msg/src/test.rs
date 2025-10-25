//! This module is only used when testing the library.
//! Any `pub use` here is also imported in the [super] module.
//! It may only be used inside tests.

use super::*;
use binrw::prelude::*;
use std::io::Cursor;

pub(crate) fn encode_content(content: RequestContent) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    let msg = PlainRequest::new(content);
    msg.write(&mut cursor).unwrap();
    let bytes_of_msg = cursor.into_inner();
    // We only want to return the content of the message, not the header. So cut the HEADER_SIZE bytes:
    bytes_of_msg[Header::STRUCT_SIZE..].to_vec()
}

/// Internal macro to test reading of content structs.
/// It writes the content with a SMB2 header, but compares only the content part
/// to the provided expected hex value.
macro_rules! test_response_read {
    // No test name
    (
        $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        test_response_read! {
            $struct_name: $struct_name {
                $($field_name : $field_value),*
            } => $hex
        }
    };
    // With test name
    (
        $test_name:ident: $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        test_response_read! {
            $test_name, Command::$struct_name => $struct_name {
                $($field_name : $field_value),*
            } => $hex
        }
    };
    (
        $test_name:ident, $command:expr => $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        pastey::paste! {
            #[test]
            fn [<test_content_ $test_name:snake _read>]() {
                use ::binrw::{io::Cursor, prelude::*};
                let hex_bytes = ::smb_tests::hex_to_u8_array! { $hex };
                let mut cursor = Cursor::new(hex_bytes);
                let msg: PlainResponse = cursor.read_le().unwrap();
                let msg: [<$struct_name Response>] = msg.content.[<to_ $struct_name:lower>]().unwrap();
                assert_eq!(msg, [<$struct_name Response>] {
                    $(
                        $field_name: $field_value,
                    )*
                });
            }
        }
    };
}

macro_rules! test_response_write {
    (
        $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        test_response_write! {
            $struct_name: $struct_name {
                $($field_name : $field_value),*
            } => $hex
        }
    };
    (
        $test_name:ident: $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        test_response_write! {
            $test_name, Command::$struct_name => $struct_name {
                $($field_name : $field_value),*
            } => $hex
        }
    };
    (
        $test_name:ident, $command:expr => $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        pastey::paste! {
            #[test]
            fn [<test_content_ $test_name:snake _write>]() {
                use ::binrw::{io::Cursor, prelude::*};
                let response = [<$struct_name Response>] {
                    $(
                        $field_name: $field_value,
                    )*
                };
                let mut cursor = Cursor::new(Vec::new());
                let mut msg = PlainResponse::new_with_command(response.into(), $command);
                msg.header.flags.set_server_to_redir(true); // Since we're writing a response, we must set this flag
                msg.write(&mut cursor).unwrap();
                let written_bytes = cursor.into_inner();
                let expected_bytes = ::smb_tests::hex_to_u8_array! { $hex };
                assert_eq!(&written_bytes[Header::STRUCT_SIZE..], &expected_bytes[Header::STRUCT_SIZE..]);
            }
        }
    }
}

/// Calls [`test_response_read`] and [`test_response_write`] macros
macro_rules! test_response {
    (
        $($v:tt)+
    ) => {
        test_response_read! {
            $($v)*
        }
        test_response_write! {
            $($v)*
        }
    }
}

pub(crate) use test_response;
pub(crate) use test_response_read;
pub(crate) use test_response_write;
