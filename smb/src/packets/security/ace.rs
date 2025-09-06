//! MS-DTYP 2.4.4: ACE

use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::packets::{binrw_util::prelude::*, guid::Guid};

use super::SID;

/// Macro for defining a bitfield for an access mask.
///
/// In windows, the upper word of access mask dword is always a set of common fields.
/// Therefore, implementing this macro helps saving bunch of code for different access masks.
///
/// It's input is the name of the struct to generate, and in {}, the list of fields to add
/// before the common fields. include support for `#[skip]` fields, without visibility (all fields are public).
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
    #[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
    #[bw(map = |&x| Self::into_bytes(x))]
    #[br(map = Self::from_bytes)]
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
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ACE {
    #[bw(calc = value.get_type())]
    pub ace_type: AceType,
    pub ace_flags: AceFlags,
    #[bw(calc = PosMarker::default())]
    _ace_size: PosMarker<u16>,
    #[br(args(ace_type))]
    #[br(map_stream = |s| s.take_seek(_ace_size.value as u64 - Self::HEADER_SIZE))]
    #[bw(write_with = PosMarker::write_size_plus, args(&_ace_size, Self::HEADER_SIZE))]
    pub value: AceValue,
}

impl ACE {
    const HEADER_SIZE: u64 = 4;

    /// Returns the type of the ACE.
    ///
    /// Can also be accessed by [`ACE::value`][`ACE::value`][`.get_type()`][`AceValue::get_type()`].
    #[inline]
    pub fn ace_type(&self) -> AceType {
        self.value.get_type()
    }
}

macro_rules! make_ace_value {
    (
        $($type:ident($val:ident),)+
    ) => {
        paste::paste! {

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
#[br(import(ace_type: AceType))]
pub enum AceValue {
    $(
        #[br(pre_assert(matches!(ace_type, AceType::$type)))]
        $type($val),
    )+
}

impl AceValue {
    pub fn get_type(&self) -> AceType {
        match self {
            $(
                AceValue::$type(_) => AceType::$type,
            )+
        }
    }

    $(
        pub fn [<unwrap_ $type:snake>](&self) -> &$val {
            match self {
                AceValue::$type(v) => v,
                _ => panic!("Called unwrap_{} on a different AceValue variant", stringify!($type).to_lowercase()),
            }
        }

        pub fn [<as_ $type:snake>](&self) -> Option<&$val> {
            match self {
                AceValue::$type(v) => Some(v),
                _ => None,
            }
        }

        pub fn [<as_mut_ $type:snake>](&mut self) -> Option<&mut $val> {
            match self {
                AceValue::$type(v) => Some(v),
                _ => None,
            }
        }
    )+
}

        }
    };
}

make_ace_value! {
    AccessAllowed(AccessAce),
    AccessDenied(AccessAce),
    SystemAudit(AccessAce),
    AccessAllowedObject(AccessObjectAce),
    AccessDeniedObject(AccessObjectAce),
    SystemAuditObject(AccessObjectAce),
    AccessAllowedCallback(AccessCallbackAce),
    AccessDeniedCallback(AccessCallbackAce),
    AccessAllowedCallbackObject(AccessObjectCallbackAce),
    AccessDeniedCallbackObject(AccessObjectCallbackAce),
    SystemAuditCallback(AccessCallbackAce),
    SystemAuditCallbackObject(AccessObjectCallbackAce),
    SystemMandatoryLabel(SystemMandatoryLabelAce),
    SystemResourceAttribute(SystemResourceAttributeAce),
    SystemScopedPolicyId(AccessAce),
}

impl AceValue {
    /// Returns true if the ACE is an "access allowed" type.
    pub fn is_access_allowed(&self) -> bool {
        matches!(
            self.get_type(),
            AceType::AccessAllowed
                | AceType::AccessAllowedObject
                | AceType::AccessAllowedCallback
                | AceType::AccessAllowedCallbackObject
        )
    }

    /// Returns true if the ACE is an "access denied" type.
    pub fn is_access_denied(&self) -> bool {
        matches!(
            self.get_type(),
            AceType::AccessDenied
                | AceType::AccessDeniedObject
                | AceType::AccessDeniedCallback
                | AceType::AccessDeniedCallbackObject
        )
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
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
#[derive(Debug, PartialEq, Eq, Clone)]
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
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct ObjectAceFlags {
    pub object_type_present: bool,
    pub inherited_object_type_present: bool,
    #[skip]
    __: B30,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AccessCallbackAce {
    pub access_mask: AccessMask,
    pub sid: SID,
    #[br(parse_with = binrw::helpers::until_eof)]
    pub application_data: Vec<u8>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
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
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SystemMandatoryLabelAce {
    pub mask: MandatoryLabelAccessMask,
    pub sid: SID,
}
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SystemResourceAttributeAce {
    pub mask: AccessMask,
    pub sid: SID,
    pub attribute_data: ClaimSecurityAttributeRelativeV1,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
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
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
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
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
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
