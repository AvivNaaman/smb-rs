//! MS-DTYP 2.4.4: ACE

use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::packets::{binrw_util::prelude::*, guid::Guid};

use super::SID;

/// Macro for defining a bitfield for an access mask.
/// It's input is the name of the struct to generate, and in {}, the list of fields to add
/// before the common fields. include support for #[skip] fields, without visibility (all fields are public).
#[macro_export]
macro_rules! access_mask {
    (
        $vis:vis struct $name:ident {
        $(
            $(#[$field_meta:meta])*
            $field_name:ident : $field_ty:ty,
        )*
    }) => {

    #[bitfield]
    #[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
    #[bw(map = |&x| Self::into_bytes(x))]
        $vis struct $name {
            // User fields
            $(
                $(#[$field_meta])*
                pub $field_name : $field_ty,
            )*

            pub delete: bool,
            pub read_control: bool,
            pub write_dacl: bool,
            pub write_owner: bool,

            pub synchronize: bool,
            #[skip]
            __: B3,

            pub access_system_security: bool,
            pub maximum_allowed: bool,
            #[skip]
            __: B2,

            pub generic_all: bool,
            pub generic_execute: bool,
            pub generic_write: bool,
            pub generic_read: bool,
        }
    };

}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ACE {
    #[bw(calc = value.get_type())]
    pub ace_type: AceType,
    pub ace_flags: AceFlags,
    #[bw(calc = PosMarker::default())]
    _ace_size: PosMarker<u16>,
    #[br(args(ace_type))]
    #[br(map_stream = |s| s.take_seek(_ace_size.value as u64))]
    #[bw(write_with = PosMarker::write_size, args(&_ace_size))]
    pub value: AceValue,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(ace_type: AceType))]
pub enum AceValue {
    #[br(pre_assert(matches!(ace_type, AceType::AccessAllowed)))]
    AccessAllowed(AccessAce),
    #[br(pre_assert(matches!(ace_type, AceType::AccessDenied)))]
    AccessDenied(AccessAce),
    #[br(pre_assert(matches!(ace_type, AceType::SystemAudit)))]
    SystemAudit(AccessAce),

    #[br(pre_assert(matches!(ace_type, AceType::AccessAllowedObject)))]
    AccessAllowedObject(AccessObjectAce),
    #[br(pre_assert(matches!(ace_type, AceType::AccessDeniedObject)))]
    AccessDeniedObject(AccessObjectAce),
    #[br(pre_assert(matches!(ace_type, AceType::SystemAuditObject)))]
    SystemAuditObject(AccessObjectAce),

    #[br(pre_assert(matches!(ace_type, AceType::AccessAllowedCallback)))]
    AccessAllowedCallback(AccessCallbackAce),
    #[br(pre_assert(matches!(ace_type, AceType::AccessDeniedCallback)))]
    AccessDeniedCallback(AccessCallbackAce),

    #[br(pre_assert(matches!(ace_type, AceType::AccessAllowedCallbackObject)))]
    AccessAllowedCallbackObject(AccessObjectCallbackAce),
    #[br(pre_assert(matches!(ace_type, AceType::AccessDeniedCallbackObject)))]
    AccessDeniedCallbackObject(AccessObjectCallbackAce),
    #[br(pre_assert(matches!(ace_type, AceType::SystemAuditCallback)))]
    SystemAuditCallback(AccessCallbackAce),
    #[br(pre_assert(matches!(ace_type, AceType::SystemAuditCallbackObject)))]
    SystemAuditCallbackObject(AccessObjectCallbackAce),

    #[br(pre_assert(matches!(ace_type, AceType::SystemMandatoryLabel)))]
    SystemMandatoryLabel(SystemMandatoryLabelAce),
    #[br(pre_assert(matches!(ace_type, AceType::SystemResourceAttribute)))]
    SystemResourceAttribute(SystemResourceAttributeAce),
    #[br(pre_assert(matches!(ace_type, AceType::SystemScopedPolicyId)))]
    SystemScopedPolicyId(AccessAce),
}

impl AceValue {
    pub fn get_type(&self) -> AceType {
        match self {
            AceValue::AccessAllowed(_) => AceType::AccessAllowed,
            AceValue::AccessDenied(_) => AceType::AccessDenied,
            AceValue::SystemAudit(_) => AceType::SystemAudit,
            AceValue::AccessAllowedObject(_) => AceType::AccessAllowedObject,
            AceValue::AccessDeniedObject(_) => AceType::AccessDeniedObject,
            AceValue::SystemAuditObject(_) => AceType::SystemAuditObject,
            AceValue::AccessAllowedCallback(_) => AceType::AccessAllowedCallback,
            AceValue::AccessDeniedCallback(_) => AceType::AccessDeniedCallback,
            AceValue::AccessAllowedCallbackObject(_) => AceType::AccessAllowedCallbackObject,
            AceValue::AccessDeniedCallbackObject(_) => AceType::AccessDeniedCallbackObject,
            AceValue::SystemAuditCallback(_) => AceType::SystemAuditCallback,
            AceValue::SystemAuditCallbackObject(_) => AceType::SystemAuditCallbackObject,
            AceValue::SystemMandatoryLabel(_) => AceType::SystemMandatoryLabel,
            AceValue::SystemResourceAttribute(_) => AceType::SystemResourceAttribute,
            AceValue::SystemScopedPolicyId(_) => AceType::SystemScopedPolicyId,
        }
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct AccessAce {
    pub access_mask: AccessMask,
    pub sid: SID,
}

access_mask! {
pub struct AccessMask {
    common: B16,
}}

access_mask! {
pub struct ObjectAccessMask {
    crate_child: bool,
    delete_child: bool,
    #[skip]
    __: bool,
    ds_self: bool,

    read_prop: bool,
    write_prop: bool,
    #[skip]
    __: B2,

    control_access: bool,
    #[skip]
    __: B7,
}}

access_mask! {
pub struct MandatoryLabelAccessMask {
    no_write_up: bool,
    no_read_up: bool,
    no_execute_up: bool,
    #[skip]
    __: B13,
}}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct AccessObjectAce {
    pub access_mask: ObjectAccessMask,
    #[bw(calc = ObjectAceFlags::new().with_object_type_present(object_type.is_some()).with_inherited_object_type_present(inherited_object_type.is_some()))]
    pub flags: ObjectAceFlags,
    #[br(if(flags.object_type_present()))]
    pub object_type: Option<Guid>,
    #[br(if(flags.inherited_object_type_present()))]
    pub inherited_object_type: Option<Guid>,
    pub sid: SID,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct ObjectAceFlags {
    pub object_type_present: bool,
    pub inherited_object_type_present: bool,
    #[skip]
    __: B30,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct AccessCallbackAce {
    pub access_mask: AccessMask,
    pub sid: SID,
    #[br(parse_with = binrw::helpers::until_eof)]
    pub application_data: Vec<u8>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct AccessObjectCallbackAce {
    pub access_mask: ObjectAccessMask,
    #[bw(calc = ObjectAceFlags::new().with_object_type_present(object_type.is_some()).with_inherited_object_type_present(inherited_object_type.is_some()))]
    pub flags: ObjectAceFlags,
    #[br(if(flags.object_type_present()))]
    pub object_type: Option<Guid>,
    #[br(if(flags.inherited_object_type_present()))]
    pub inherited_object_type: Option<Guid>,
    pub sid: SID,
    #[br(parse_with = binrw::helpers::until_eof)]
    pub application_data: Vec<u8>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SystemMandatoryLabelAce {
    pub mask: MandatoryLabelAccessMask,
    pub sid: SID,
}
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SystemResourceAttributeAce {
    pub mask: AccessMask,
    pub sid: SID,
    pub attribute_data: ClaimSecurityAttributeRelativeV1,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ClaimSecurityAttributeRelativeV1 {
    #[bw(calc = PosMarker::default())]
    _name: PosMarker<u32>, // TODO: Figure out what this is.
    pub value_type: ClaimSecurityAttributeType,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
    pub flags: FciClaimSecurityAttributes,
    value_count: u32,
    #[br(parse_with = binrw::helpers::until_eof)]
    pub value: Vec<u8>, // TODO: Use concrete types
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u16))]
pub enum ClaimSecurityAttributeType {
    None = 0,
    Int64 = 1,
    Uint64 = 2,
    String = 3,
    SID = 4,
    Boolean = 5,
    OctetString = 6,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct FciClaimSecurityAttributes {
    pub non_inheritable: bool,
    pub value_case_sensitive: bool,
    pub use_for_deny_only: bool,
    pub disabled_by_default: bool,

    pub disabled: bool,
    pub mandatory: bool,
    #[skip]
    __: B2,

    pub manual: bool,
    pub policy_derived: bool,
    #[skip]
    __: B6,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u8))]
pub enum AceType {
    AccessAllowed = 0,
    AccessDenied = 1,
    SystemAudit = 2,
    SystemAlarm = 3,
    AccessAllowedCompound = 4,
    AccessAllowedObject = 5,
    AccessDeniedObject = 6,
    SystemAuditObject = 7,
    SystemAlarmObject = 8,
    AccessAllowedCallback = 9,
    AccessDeniedCallback = 10,
    AccessAllowedCallbackObject = 11,
    AccessDeniedCallbackObject = 12,
    SystemAuditCallback = 13,
    SystemAlarmCallback = 14,
    SystemAuditCallbackObject = 15,
    SystemAlarmCallbackObject = 16,
    SystemMandatoryLabel = 17,
    SystemResourceAttribute = 18,
    SystemScopedPolicyId = 19,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct AceFlags {
    pub object_inherit: bool,
    pub container_inherit: bool,
    pub no_propagate_inherit: bool,
    pub inherit_only: bool,

    pub inherited: bool,
    #[skip]
    __: bool,
    pub successful_access: bool,
    pub failed_access: bool,
}
