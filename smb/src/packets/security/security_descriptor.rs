//! MS-DTYP 2.4.6: Security Descriptor

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::packets::binrw_util::prelude::*;

use super::{ACL, SID};

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(little)]
pub struct SecurityDescriptor {
    #[bw(calc = 1)]
    #[br(assert(_revision == 1))]
    _revision: u8,
    pub sbz1: u8,
    #[brw(assert(control.self_relative()))]
    pub control: SecurityDescriptorControl,
    #[bw(calc = PosMarker::default())]
    offset_owner: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    offset_group: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    offset_sacl: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    offset_dacl: PosMarker<u32>,
    #[br(if(offset_owner.value != 0))]
    pub owner_sid: Option<SID>,
    #[br(if(offset_group.value != 0))]
    pub group_sid: Option<SID>,
    #[bw(assert(sacl.is_some() == control.sacl_present()))]
    #[br(assert((offset_sacl.value != 0) == (control.sacl_present())))]
    #[br(if(offset_sacl.value != 0))]
    pub sacl: Option<ACL>,
    #[bw(assert(dacl.is_some() == control.dacl_present()))]
    #[br(assert((offset_dacl.value != 0) == control.dacl_present()))]
    #[br(if(offset_dacl.value != 0))]
    pub dacl: Option<ACL>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SecurityDescriptorControl {
    pub owner_defaulted: bool,
    pub group_defaulted: bool,
    pub dacl_present: bool,
    pub dacl_defaulted: bool,

    pub sacl_present: bool,
    pub sacl_defaulted: bool,
    pub dacl_trusted: bool,
    pub server_security: bool,

    pub dacl_computed: bool,
    pub sacl_computed: bool,
    pub dacl_auto_inherited: bool,
    pub sacl_auto_inherited: bool,

    pub dacl_protected: bool,
    pub sacl_protected: bool,
    pub rm_control_valid: bool,
    pub self_relative: bool,
}
