use binrw::prelude::*;
use rand::Rng;
use sspi::{AuthIdentity, Secret, Username};
use std::{cell::OnceCell, error::Error, fmt::Display};

use crate::{
    authenticator::GssAuthenticator,
    netbios_client::NetBiosClient,
    packets::{
        netbios::NetBiosMessageContent,
        smb1::SMB1NegotiateMessage,
        smb2::{
            header::{SMB2Command, SMB2HeaderFlags, SMB2Status},
            message::{SMB2Message, SMBMessageContent},
            negotiate::{SMBDialect, SMBNegotiateRequest, SMBNegotiateResponseDialect},
            setup::SMB2SessionSetupRequest,
        },
    },
};

struct SmbNegotiateState {
    server_guid: u128,

    max_transact_size: u32,
    max_read_size: u32,
    max_write_size: u32,

    gss_negotiate_token: Vec<u8>,

    selected_dialect: SMBDialect
}

pub struct SMBClient {
    client_guid: u128,
    netbios_client: NetBiosClient,
    current_message_id: u64,

    // Negotiation-related state.
    negotiate_state: OnceCell<SmbNegotiateState>,

    session_id: u64,
}

#[derive(Debug, Clone)]
pub struct SmbClientNotConnectedError;

impl Display for SmbClientNotConnectedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SMB client is not connected")
    }
}

impl Error for SmbClientNotConnectedError {}

impl SMBClient {
    pub fn new() -> SMBClient {
        SMBClient {
            client_guid: rand::rngs::OsRng.gen(),
            netbios_client: NetBiosClient::new(),
            negotiate_state: OnceCell::new(),
            current_message_id: 0,
            session_id: 0,
        }
    }

    pub fn connect(&mut self, address: &str) -> Result<(), Box<dyn Error>> {
        self.netbios_client.connect(address)
    }

    fn receive_smb2(
        &mut self,
        command: SMB2Command,
        require_success: bool,
    ) -> Result<SMB2Message, Box<dyn Error>> {
        let netbios_message = self.netbios_client.receive()?;
        let smb2_message = match netbios_message {
            NetBiosMessageContent::SMB2Message(smb2_message) => Some(smb2_message),
            _ => None,
        }
        .ok_or("Expected SMB2 message")?;
        if smb2_message.header.command != command {
            return Err("Unexpected SMB2 command".into());
        };
        if !smb2_message.header.flags.server_to_redir() {
            return Err("Unexpected SMB2 message direction (Not a response)".into());
        }
        if require_success && smb2_message.header.status != SMB2Status::Success as u32 {
            return Err("SMB2 message status is not success".into());
        }
        Ok(smb2_message)
    }

    fn send_and_receive_smb2(
        &mut self,
        message: SMBMessageContent,
        require_success: bool
    ) -> Result<SMB2Message, Box<dyn Error>> {
        self.current_message_id += 1;
        // TODO: Add assertion in the struct regarding the selected dialect!
        let priority_value = match self.negotiate_state.get() {
            Some(negotiate_state) => match (negotiate_state.selected_dialect) {
                SMBDialect::Smb0311 => 1,
                _ => 0,
            },
            None => 0,
        };
        let flags = SMB2HeaderFlags::new().with_priority_mask(priority_value);
        let message_with_header = SMB2Message::new(
            message,
            self.current_message_id,
            1,
            1,
            flags,
            self.session_id,
        );
        let command = message_with_header.header.command;
        self.netbios_client
            .send(NetBiosMessageContent::SMB2Message(message_with_header))?;
        self.receive_smb2(command, require_success)
    }

    fn negotiate_smb1(&mut self) -> Result<(), Box<dyn Error>> {
        // 1. Send SMB1 negotiate request
        self.netbios_client
            .send(NetBiosMessageContent::SMB1Message(
                SMB1NegotiateMessage::new(),
            ))?;

        // 2. Expect SMB2 negotiate response
        let smb2_response = self.receive_smb2(SMB2Command::Negotiate, true)?;
        let smb2_negotiate_response = match smb2_response.content {
            SMBMessageContent::SMBNegotiateResponse(response) => Some(response),
            _ => None,
        }
        .unwrap();

        // 3. Make sure dialect is smb2*
        if smb2_negotiate_response.dialect_revision != SMBNegotiateResponseDialect::Smb02Wildcard {
            return Err("Unexpected SMB2 dialect revision".into());
        }
        Ok(())
    }

    fn negotiate_smb2(&mut self) -> Result<(), Box<dyn Error>> {
        // Send SMB2 negotiate request
        let smb2_response = self.send_and_receive_smb2(
            SMBMessageContent::SMBNegotiateRequest(SMBNegotiateRequest::new(self.client_guid)),
            true
        )?;
        let smb2_negotiate_response = match smb2_response.content {
            SMBMessageContent::SMBNegotiateResponse(response) => Some(response),
            _ => None,
        }
        .unwrap();

        let negotiate_state = SmbNegotiateState {
            server_guid: smb2_negotiate_response.server_guid,
            max_transact_size: smb2_negotiate_response.max_transact_size,
            max_read_size: smb2_negotiate_response.max_read_size,
            max_write_size: smb2_negotiate_response.max_write_size,
            gss_negotiate_token: smb2_negotiate_response.buffer,
            selected_dialect: smb2_negotiate_response.dialect_revision.try_into()?,
        };

        self.negotiate_state
            .set(negotiate_state)
            .map_err(|_| "Negotiate state already set")?;

        Ok(())
    }

    pub fn negotiate(&mut self) -> Result<(), Box<dyn Error>> {
        self.negotiate_smb1()?;
        self.negotiate_smb2()
    }

    pub fn authenticate(
        &mut self,
        user_name: String,
        password: String,
    ) -> Result<(), Box<dyn Error>> {
        let negotate_state = self
            .negotiate_state
            .get()
            .ok_or(SmbClientNotConnectedError)?;
        let identity = AuthIdentity {
            username: Username::new(&user_name, Some("WORKGROUP"))?,
            password: Secret::new(password),
        };
        let (mut authenticator, mut next_buf) =
            GssAuthenticator::build(&negotate_state.gss_negotiate_token, identity)?;
        let response = self.send_and_receive_smb2(
                SMBMessageContent::SMBSessionSetupRequest(SMB2SessionSetupRequest::new(next_buf)),
                false
        )?;

        if response.header.status != SMB2Status::MoreProcessingRequired as u32 {
            return Err("Expected STATUS_MORE_PROCESSING_REQUIRED".into());
        }
        let session_id = response.header.session_id;

        let mut response = Some(response);
        while !authenticator.is_authenticated()? {
            // If there's a response to process, do so.
            let last_setup_response = match response.as_ref() {
                Some(response) => Some(
                    match &response.content {
                        SMBMessageContent::SMBSessionSetupResponse(response) => Some(response),
                        _ => None,
                    }
                    .unwrap(),
                ),
                None => None,
            };

            let next_buf = match last_setup_response.as_ref() {
                Some(response) => authenticator.next(&response.buffer)?,
                None => authenticator.next(&vec![])?,
            };

            response = match next_buf {
                Some(next_buf) => Some(self.send_and_receive_smb2(
                        SMBMessageContent::SMBSessionSetupRequest(SMB2SessionSetupRequest::new(
                            next_buf,
                        )),
                        false
                )?),
                None => None,
            };
        }
        Ok(())
    }

    pub fn tree_connect(&mut self, name: String) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
