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
    (
        $test_name:ident: $struct_name:ident {
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

pub(crate) use test_response_read;
