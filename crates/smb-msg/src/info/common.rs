//! Common data structures for query/set info messages.

use binrw::prelude::*;
use modular_bitfield::prelude::*;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[brw(repr(u8))]
pub enum InfoType {
    File = 0x1,
    FileSystem = 0x2,
    Security = 0x3,
    Quota = 0x4,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct AdditionalInfo {
    pub owner_security_information: bool,
    pub group_security_information: bool,
    pub dacl_security_information: bool,
    pub sacl_security_information: bool,

    pub label_security_information: bool,
    pub attribute_security_information: bool,
    pub scope_security_information: bool,

    #[skip]
    __: B9,
    pub backup_security_information: bool,
    #[skip]
    __: B15,
}

/// Internal helper macro to easily generate fields & methods for [QueryInfoData](super::query::QueryInfoData).
///
/// Builds:
/// 1. The enum with the specified name, with variants for each info type specified.
/// 2. A generic struct names `Raw<name>` to hold the raw data, with a method to convert it to the actual data.
#[macro_export]
macro_rules! query_info_data {
    ($name:ident $($info_type:ident: $content:ty, )+) => {
        paste::paste! {
            #[allow(unused_imports)]
            use binrw::prelude::*;
            #[allow(unused_imports)]
            use binrw::meta::WriteEndian;
            /// Represents information passed in get/set info requests.
            /// This is the information matching [InfoType], and should be used
            /// in the get info response and in the set info request.
            #[binrw::binrw]
            #[derive(Debug)]
            #[brw(little)]
            #[br(import(info_type: InfoType))]
            pub enum $name {
                $(
                    #[br(pre_assert(info_type == InfoType::$info_type))]
                    $info_type($content),
                )+
            }

            impl $name {
                // unwrap_ methods to easily get the inner content.
                $(
                    pub fn [<unwrap_ $info_type:lower>](self) -> $content {
                        match self {
                            $name::$info_type(data) => data,
                            _ => panic!("Expected $info_type, got {:?}", self),
                        }
                    }
                    pub fn [<as_ $info_type:lower>](self) -> Result<$content, $crate::SmbMsgError> {
                        match self {
                            $name::$info_type(data) => Ok(data),
                            _ => Err($crate::SmbMsgError::UnexpectedContent {
                                expected: stringify!($info_type),
                                actual: self.name(),
                            }),
                        }
                    }
                )+

                /// Get the [InfoType] of this data.
                pub fn info_type(&self) -> InfoType {
                    match self {
                        $(
                            $name::$info_type(_) => InfoType::$info_type,
                        )+
                    }
                }

                /// Get the name of this data.
                pub fn name(&self) -> &'static str {
                    match self {
                        $(
                            $name::$info_type(_) => stringify!($info_type),
                        )+
                    }
                }
            }

            /// Content to enum conversions:
            $(
                impl From<$content> for $name {
                    fn from(value: $content) -> Self {
                        $name::$info_type(value)
                    }
                }
            )+

            // All same for filesystem:
            #[binrw::binrw]
            #[derive(Debug)]
            pub struct [<Raw $name>]<T>
            where
                T: Sized,
            {
                #[br(parse_with = binrw::helpers::until_eof)]
                data: Vec<u8>,

                phantom: std::marker::PhantomData<T>,
            }


            impl<T> [<Raw $name>]<T>
            where
                T: Sized,
            {
                pub fn data(&self) -> &[u8] {
                    &self.data
                }
            }

            impl<T> [<Raw $name>]<T>
            where
                T: Sized,
                T: BinRead<Args<'static> = (T::Class,)> + FileInfoType,
            {
                // A parse method that accepts the class of T as an argument, reads the data and returns the T.
                pub fn parse(&self, class: T::Class) -> Result<T, $crate::SmbMsgError> {
                    let mut cursor = std::io::Cursor::new(&self.data);
                    let value = T::read_le_args(&mut cursor, (class,))?;
                    Ok(value)
                }
            }

            impl<T> From<T> for [<Raw $name>]<T>
            where
                for<'a> T: BinWrite<Args<'a> = ()>,
            {
                fn from(value: T) -> Self {
                    let mut cursor = std::io::Cursor::new(Vec::new());
                    value.write_le(&mut cursor).unwrap();
                    Self {
                        data: cursor.into_inner(),
                        phantom: std::marker::PhantomData,
                    }
                }
            }
        }
    };
}
