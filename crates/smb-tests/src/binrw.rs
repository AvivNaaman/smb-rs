//! Test utilities for binrw-related code.

/// BinWrite test macro.
///
/// Creates a test
/// ```ignore
/// test_binrw_write! {
///     StructName {
///         field1: value1,
///         field2: value2,
///         // ...
///     }: [byte1, byte2, byte3, ...]
/// }
/// ```
#[macro_export]
macro_rules! test_binrw_write {
    (
        $name:ident {
            $(
                $field:ident : $value:expr,
            )+
        }: [$($bytes:expr),* $(,)?]
    ) => {
        pastey::paste! {
            #[test]
            fn [<test_ $name:snake _write>]() {
                use ::binrw::{prelude::*, io::Cursor};
                let value = $name {
                    $($field: $value),*
                };

                $crate::binrw_write_and_assert_eq!(
                    value,
                    [$($bytes),*]
                );
            }
        }

    };
}

#[macro_export]
macro_rules! binrw_write_and_assert_eq {
    (
        $value:expr,
        [$($bytes:expr),* $(,)?]
    ) => {
        {
            use ::binrw::{prelude::*, io::Cursor};
            let mut writer = Cursor::new(Vec::new());
            $value.write_le(&mut writer).unwrap();
            let expected: Vec<u8> = vec![$($bytes),*];
            assert_eq!(writer.into_inner(), expected);
        }
    };
}

/// BinRead test macro.
/// ```ignore
/// test_binrw_read! {
///     StructName {
///         field1: value1,
///         field2: value2,
///         // ...
///     }: [byte1, byte2, byte3, ...]
/// }
/// ```
#[macro_export]
macro_rules! test_binrw_read {
    (
        $name:ident {
            $(
                $field:ident : $value:expr,
            )+
        }: [$($bytes:expr),* $(,)?]
    ) => {
        pastey::paste! {
            #[test]
            fn [<test_ $name:snake _read>]() {
                use ::binrw::{prelude::*, io::Cursor};
                let bytes: &'static [u8] = &[$($bytes),*];
                let mut reader = Cursor::new(bytes);
                let value: $name = $name::read_le(&mut reader).unwrap();
                let expected = $name {
                    $($field: $value),*
                };
                assert_eq!(value, expected);
            }
        }

    };
}

pub use binrw_write_and_assert_eq;
pub use test_binrw_read;
pub use test_binrw_write;
