//! Framework for implementing FSCC Info Classes

use binrw::{meta::ReadEndian, prelude::*};

/// Trait for file information types.
/// This trait contains all types of all file info types and classes, specified in MS-FSCC.
///
/// It's role is to allow converting an instance of a file information type to a class,
/// and to provide the class type from the file information type.
pub trait FileInfoType:
    Sized + for<'a> BinRead<Args<'static> = (Self::Class,)> + ReadEndian + std::fmt::Debug
{
    /// The class of the file information.
    type Class;

    /// Get the class of the file information.
    fn class(&self) -> Self::Class;
}

/// A macro for generating a file class enums,
/// for both the file information class, and information value.
/// including a trait for the value types.
#[macro_export]
macro_rules! file_info_classes {
    (
        $svis:vis $name:ident {
            $($vis:vis $field_name:ident = $cid:literal,)+
        }, $brw_ty:ty
    ) => {
        #[allow(unused_imports)]
        use binrw::prelude::*;
        pastey::paste! {
            // Trait to be implemented for all the included value types.
            pub trait [<$name Value>] :
                TryFrom<$name, Error = $crate::SmbFsccError>
                + Send + 'static
                + Into<$name>
                + for <'a> [<Bin $brw_ty>]<Args<'a> = ()> {
                const CLASS_ID: [<$name Class>];
            }

            // Enum for Class IDs
            #[binrw::binrw]
            #[derive(Debug, PartialEq, Eq, Clone, Copy)]
            #[brw(repr(u8))]
            $svis enum [<$name Class>] {
                $(
                    $vis [<$field_name Information>] = $cid,
                )*
            }

            // Enum for class values
            #[binrw::binrw]
            #[derive(Debug, PartialEq, Eq)]
            #[brw(little)]
            #[br(import(c: [<$name Class>]))]
            $svis enum $name {
                $(
                    #[br(pre_assert(matches!(c, [<$name Class>]::[<$field_name Information>])))]
                    [<$field_name Information>]([<File $field_name Information>]),
                )*
            }

            impl std::fmt::Display for [<$name Class>] {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    match self {
                        $(
                            [<$name Class>]::[<$field_name Information>] => write!(f, stringify!([<$field_name Information>])),
                        )*
                    }
                }
            }

            impl $crate::FileInfoType for $name {
                type Class = [<$name Class>];
                fn class(&self) -> Self::Class {
                    match self {
                        $(
                            $name::[<$field_name Information>](_) => [<$name Class>]::[<$field_name Information>],
                        )*
                    }
                }
            }

            $(
                impl From<[<File $field_name Information>]> for $name {
                    fn from(value: [<File $field_name Information>]) -> $name {
                        $name::[<$field_name Information>](value)
                    }
                }

                impl TryFrom<$name> for [<File $field_name Information>] {
                    type Error = $crate::SmbFsccError;

                    fn try_from(value: $name) -> Result<Self, Self::Error> {
                        pub use $crate::FileInfoType;
                        match value {
                            $name::[<$field_name Information>](v) => Ok(v),
                            _ => Err($crate::SmbFsccError::UnexpectedInformationType(<Self as [<$name Value>]>::CLASS_ID as u8, value.class() as u8)),
                        }
                    }
                }

                impl [<$name Value>] for [<File $field_name Information>] {
                    const CLASS_ID: [<$name Class>] = [<$name Class>]::[<$field_name Information>];
                }
            )*
        }
    }
}
