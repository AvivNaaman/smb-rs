use super::compressed::*;
use super::encrypted::*;
use super::plain::*;
use binrw::prelude::*;

macro_rules! make_message {
    ($name:ident, $derive_attr:ty, $plain_type:ty) => {
        #[derive($derive_attr, Debug)]
        #[brw(little)]
        pub enum $name {
            Plain($plain_type),
            Encrypted(EncryptedMessage),
            Compressed(CompressedMessage),
        }
    };
}

make_message!(Request, BinWrite, PlainRequest);
make_message!(Response, BinRead, PlainResponse);

impl TryFrom<&[u8]> for Response {
    type Error = binrw::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Response::read(&mut std::io::Cursor::new(value))
    }
}
