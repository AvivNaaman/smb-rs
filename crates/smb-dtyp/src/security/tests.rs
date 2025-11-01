use super::*;
use std::str::FromStr;

use binrw::prelude::*;
use smb_tests::*;

test_binrw! {
    SecurityDescriptor => owner_group:
    SecurityDescriptor {
        sbz1: 0,
        control: SecurityDescriptorControl::new().with_self_relative(true),
        owner_sid: Some(SID::from_str("S-1-5-21-782712087-4182988437-2163400469-1001").unwrap()),
        group_sid: Some(SID::from_str("S-1-5-21-782712087-4182988437-2163400469-1001").unwrap()),
        sacl: None,
        dacl: None,
    } => "0100008014000000300000000000000000000000010500000000000515000000173da72e955653f915dff280
    e9030000010500000000000515000000173da72e955653f915dff280e9030000"
}

test_binrw! {
    SecurityDescriptor => dacl_only_sd: SecurityDescriptor {
        sbz1: 0,
        control: SecurityDescriptorControl::new()
            .with_self_relative(true)
            .with_dacl_auto_inherited(true)
            .with_dacl_present(true),
        owner_sid: None,
        group_sid: None,
        sacl: None,
        dacl: ACL {
            acl_revision: AclRevision::Nt4,
            ace: vec![
                ACE {
                    ace_flags: AceFlags::new()
                        .with_inherited(true)
                        .with_container_inherit(true)
                        .with_object_inherit(true),
                    value: AceValue::AccessAllowed(AccessAce {
                        access_mask: AccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                        sid: SID::from_str("S-1-5-21-782712087-4182988437-2163400469-1001")
                            .unwrap(),
                    }),
                },
                ACE {
                    ace_flags: AceFlags::new()
                        .with_inherited(true)
                        .with_container_inherit(true)
                        .with_object_inherit(true),
                    value: AceValue::AccessAllowed(AccessAce {
                        access_mask: AccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                        sid: SID::from_str(SID::S_ADMINISTRATORS).unwrap(),
                    }),
                },
                ACE {
                    ace_flags: AceFlags::new()
                        .with_inherited(true)
                        .with_container_inherit(true)
                        .with_object_inherit(true),
                    value: AceValue::AccessAllowed(AccessAce {
                        access_mask: AccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                        sid: SID::from_str(SID::S_LOCAL_SYSTEM).unwrap(),
                    }),
                },
                ACE {
                    ace_flags: AceFlags::new()
                        .with_inherited(true)
                        .with_container_inherit(true)
                        .with_object_inherit(true),
                    value: AceValue::AccessAllowed(AccessAce {
                        access_mask: AccessMask::from_bytes(0x1200a9u32.to_le_bytes()),
                        sid: SID::from_str(SID::S_EVERYONE).unwrap(),
                    }),
                },
                ACE {
                    ace_flags: AceFlags::new()
                        .with_inherited(true)
                        .with_container_inherit(true)
                        .with_object_inherit(true),
                    value: AceValue::AccessAllowed(AccessAce {
                        access_mask: AccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                        sid: SID::from_str("S-1-5-21-782712087-4182988437-2163400469-1002")
                            .unwrap(),
                    }),
                },
            ],
        }
        .into(),
    } => "0100048400000000000000000000000014000000020090000500000000
    132400ff011f00010500000000000515000000173da72e955653f915dff280
    e903000000131800ff011f0001020000000000052000000020020000001314
    00ff011f0001010000000000051200000000131400a9001200010100000000
    00010000000000132400ff011f00010500000000000515000000173da72e95
    5653f915dff280ea030000"
}
