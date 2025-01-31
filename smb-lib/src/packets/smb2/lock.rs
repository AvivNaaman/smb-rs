use super::super::guid::Guid;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct LockRequest {
    #[bw(calc = 48)]
    #[br(assert(_structure_size == 48))]
    _structure_size: u16,
    #[bw(try_calc = locks.len().try_into())]
    lock_count: u16,
    pub lock_sequence: LockSequence,
    pub file_id: Guid,
    #[br(count = lock_count)]
    pub locks: Vec<LockElement>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct LockSequence {
    pub number: B4,
    pub index: B28,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct LockElement {
    pub offset: u64,
    pub length: u64,
    pub flags: LockFlag,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u32,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct LockFlag {
    pub shared: bool,
    pub exclusive: bool,
    pub unlock: bool,
    pub fail_immediately: bool,
    #[skip]
    __: B28,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct LockResponse {
    #[bw(calc = 4)]
    #[br(assert(_structure_size == 4))]
    pub _structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    pub _reserved: u16,
}

#[cfg(test)]
pub mod tests {

    // TODO: tests
}
