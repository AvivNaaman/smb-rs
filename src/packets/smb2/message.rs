use super::encrypted::*;
use super::plain::*;
use super::compressed::*;
use binrw::prelude::*;

#[derive(BinRead, BinWrite, Debug)]
pub enum Message {
    Plain(PlainMessage),
    Encrypted(EncryptedMessage),
    Compressed(CompressedMessage),
}
