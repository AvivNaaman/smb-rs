use binrw::prelude::*;

macro_rules! make_message {
    ($name:ident, $binrw_type:ident, $plain_type:ty) => {
        #[binrw::$binrw_type]
        #[derive(Debug)]
        #[brw(little)]
        pub enum $name {
            Plain($plain_type),
            Encrypted($crate::EncryptedMessage),
            Compressed($crate::CompressedMessage),
        }
    };
}

macro_rules! make_messages {
    ($req_type:ident, $res_type:ident) => {
        make_message!(Request, $req_type, $crate::PlainRequest);
        make_message!(Response, $res_type, $crate::PlainResponse);
    };
}

#[cfg(all(feature = "client", not(feature = "server")))]
make_messages!(binwrite, binread);

#[cfg(all(feature = "server", not(feature = "client")))]
make_messages!(binread, binwrite);

#[cfg(all(feature = "server", feature = "client"))]
make_messages!(binrw, binrw);

impl TryFrom<&[u8]> for Response {
    type Error = binrw::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Response::read(&mut std::io::Cursor::new(value))
    }
}
