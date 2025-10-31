//! Data structures for NDR64.
use binrw::prelude::*;

pub mod align;
pub use align::*;
pub mod arrays;
pub use arrays::*;
pub mod string;
pub use string::*;
pub mod ptr;
pub use ptr::*;
pub mod consts;
pub use consts::*;

#[cfg(test)]
mod tests {
    use smb_tests::test_binrw;

    use super::*;

    #[binrw::binrw]
    #[derive(Debug, PartialEq, Eq)]
    struct TestNdrStringPtr {
        string: NdrPtr<NdrString<u16>>,
    }

    test_binrw! {
        struct TestNdrStringPtr {
            string: r"\\localhostt".parse::<NdrString<u16>>().unwrap().into(),
        } => "00000200000000000d0000000000000000000000000000000d000000000000005c005c006c006f00630061006c0068006f007300740074000000"
    }
}
