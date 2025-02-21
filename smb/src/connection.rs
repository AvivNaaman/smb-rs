pub mod negotiation_state;
pub mod netbios_client;
pub mod preauth_hash;
pub mod transformer;
pub mod worker;

use crate::packets::guid::Guid;
use crate::packets::smb2::{Command, Message};
use crate::sync_helpers::*;
use crate::Error;
use crate::{
    crypto,
    msg_handler::*,
    packets::{
        netbios::NetBiosMessageContent,
        smb1::SMB1NegotiateMessage,
        smb2::{negotiate::*, plain::*},
    },
    session::Session,
};
use binrw::prelude::*;
use maybe_async::*;
use negotiation_state::NegotiateState;
use netbios_client::NetBiosClient;
use std::cmp::max;
use std::sync::Arc;
pub use transformer::TransformError;
use worker::{Worker, WorkerImpl};

pub struct Connection {
    handler: HandlerReference<ConnectionMessageHandler>,
}

impl Connection {
    pub fn new() -> Connection {
        Connection {
            handler: HandlerReference::new(ConnectionMessageHandler::new()),
        }
    }
    #[maybe_async]
    pub async fn connect(&mut self, address: &str) -> crate::Result<()> {
        let mut netbios_client = NetBiosClient::new();

        log::debug!("Connecting to {}...", address);
        netbios_client.connect(address).await?;

        log::info!("Connected to {}. Negotiating.", address);
        self.negotiate(netbios_client, true).await?;

        Ok(())
    }

    #[maybe_async]
    pub async fn close(&self) -> crate::Result<()> {
        match self.handler.worker().take() {
            Some(c) => c.stop().await,
            None => Ok(()),
        }
    }

    #[maybe_async]
    async fn negotiate_switch_to_smb2(
        &mut self,
        mut netbios_client: NetBiosClient,
        negotiate_smb1: bool,
    ) -> crate::Result<Arc<WorkerImpl>> {
        // Multi-protocol negotiation.
        if negotiate_smb1 {
            log::debug!("Negotiating multi-protocol");
            // 1. Send SMB1 negotiate request
            netbios_client
                .send(NetBiosMessageContent::SMB1Message(
                    SMB1NegotiateMessage::new(),
                ))
                .await?;

            // 2. Expect SMB2 negotiate response
            let response = netbios_client.recieve_bytes().await?.parse_content()?;
            let message = match response {
                NetBiosMessageContent::SMB2Message(Message::Plain(m)) => m,
                _ => {
                    return Err(Error::InvalidMessage(
                        "Expected SMB2 negotiate response, got SMB1".to_string(),
                    ))
                }
            };

            let smb2_negotiate_response = match message.content {
                Content::NegotiateResponse(response) => Some(response),
                _ => None,
            }
            .ok_or(Error::InvalidMessage(
                "Expected Negotiate response.".to_string(),
            ))?;

            // 3. Make sure dialect is smb2*, message ID is 0.
            if smb2_negotiate_response.dialect_revision != NegotiateDialect::Smb02Wildcard {
                return Err(Error::InvalidMessage(
                    "Expected SMB2 wildcard dialect".to_string(),
                ));
            }
            if message.header.message_id != 0 {
                return Err(Error::InvalidMessage("Expected message ID 0".to_string()));
            }
        }

        Ok(WorkerImpl::start(netbios_client).await?)
    }

    #[maybe_async]
    async fn negotiate_smb2(&mut self) -> crate::Result<()> {
        // Confirm that we're not already negotiated.
        if self.handler.negotiate_state().is_some() {
            return Err(Error::InvalidState("Already negotiated".into()));
        }

        log::debug!("Negotiating SMB2");

        // Send SMB2 negotiate request
        let client_guid = self.handler.client_guid;
        let response = self
            .handler
            .send_recv(Content::NegotiateRequest(NegotiateRequest::new(
                "AVIV-MBP".to_string(),
                client_guid,
                crypto::SIGNING_ALGOS.into(),
                crypto::ENCRYPTING_ALGOS.to_vec(),
            )))
            .await?;

        let smb2_negotiate_response = match response.message.content {
            Content::NegotiateResponse(response) => Some(response),
            _ => None,
        }
        .ok_or(Error::InvalidMessage(
            "Expected Negotiate response.".to_string(),
        ))?;

        // well, only 3.1 is supported for starters.
        if smb2_negotiate_response.dialect_revision != NegotiateDialect::Smb0311 {
            return Err(Error::UnsupportedDialect(
                smb2_negotiate_response.dialect_revision,
            ));
        }

        if let None = smb2_negotiate_response.negotiate_context_list {
            return Err(Error::InvalidMessage(
                "Expected negotiate context list".to_string(),
            ));
        }

        let signing_algo: SigningAlgorithmId = smb2_negotiate_response.get_signing_algo().unwrap();
        if !crypto::SIGNING_ALGOS.contains(&signing_algo) {
            return Err(Error::NegotiationError(
                "Unsupported signing algorithm received".into(),
            ));
        }

        // Make sure preauth integrity capability is SHA-512, if it exists in response:
        if let Some(algo) = smb2_negotiate_response.get_preauth_integrity_algo() {
            if !preauth_hash::SUPPORTED_ALGOS.contains(&algo) {
                return Err(Error::NegotiationError(
                    "Unsupported preauth integrity algorithm received".into(),
                ));
            }
        }

        // And verify that the encryption algorithm is supported.
        let encryption_cipher = smb2_negotiate_response.get_encryption_cipher().unwrap();
        if !crypto::ENCRYPTING_ALGOS.contains(&encryption_cipher) {
            return Err(Error::NegotiationError(
                "Unsupported encryption algorithm received".into(),
            ));
        }

        let compression: Option<CompressionCaps> = match smb2_negotiate_response.get_compression() {
            Some(compression) => Some(compression.clone()),
            None => None,
        };

        let negotiate_state = NegotiateState {
            server_guid: smb2_negotiate_response.server_guid,
            global_caps: smb2_negotiate_response.capabilities.clone(),
            max_transact_size: smb2_negotiate_response.max_transact_size,
            max_read_size: smb2_negotiate_response.max_read_size,
            max_write_size: smb2_negotiate_response.max_write_size,
            gss_token: smb2_negotiate_response.buffer,
            selected_dialect: smb2_negotiate_response.dialect_revision.try_into()?,
            signing_algo,
            encryption_cipher,
            compression,
        };
        log::trace!(
            "Negotiated SMB results: dialect={:?}, state={:?}",
            negotiate_state.selected_dialect,
            &negotiate_state
        );

        self.handler.negotiate_state.set(negotiate_state).unwrap();

        Ok(())
    }

    /// Send negotiate messages, potentially
    #[maybe_async]
    async fn negotiate(
        &mut self,
        netbios_client: NetBiosClient,
        multi_protocol: bool,
    ) -> crate::Result<()> {
        if self.handler.negotiate_state().is_some() {
            return Err(Error::InvalidState("Already negotiated".into()));
        }

        // Negotiate SMB1, Switch to SMB2
        let worker = self
            .negotiate_switch_to_smb2(netbios_client, multi_protocol)
            .await?;

        self.handler.worker.set(worker).unwrap();

        // Negotiate SMB2
        self.negotiate_smb2().await?;
        self.handler
            .worker
            .get()
            .ok_or("Worker is uninitialized")
            .unwrap()
            .negotaite_complete(&self.handler.negotiate_state().unwrap())
            .await;
        log::info!("Negotiation successful");
        Ok(())
    }

    #[maybe_async]
    pub async fn authenticate(
        self: &mut Connection,
        user_name: String,
        password: String,
    ) -> crate::Result<Session> {
        let mut session = Session::new(self.handler.clone());

        session.setup(user_name, password).await?;

        Ok(session)
    }
}

/// This struct is the internal message handler for the SMB client.
pub struct ConnectionMessageHandler {
    client_guid: Guid,
    /// The number of extra credits to be requested by the client
    /// to enable larger requests/multiple outstanding requests.
    extra_credits_to_request: u16,

    worker: OnceCell<Arc<WorkerImpl>>,

    // Negotiation-related state.
    negotiate_state: OnceCell<NegotiateState>,
    sequence_state: Mutex<SequenceState>,
}

struct SequenceState {
    /// sequence low
    curr_msg_id: u64,
    /// sequence size
    curr_credits: u16,
}

impl ConnectionMessageHandler {
    fn new() -> ConnectionMessageHandler {
        ConnectionMessageHandler {
            client_guid: Guid::gen(),
            worker: OnceCell::new(),
            negotiate_state: OnceCell::new(),
            extra_credits_to_request: 16 * 4,
            sequence_state: Mutex::new(SequenceState {
                curr_msg_id: 1,
                curr_credits: 1,
            }),
        }
    }

    pub fn negotiate_state(&self) -> Option<&NegotiateState> {
        self.negotiate_state.get()
    }

    pub fn worker(&self) -> Option<&Arc<WorkerImpl>> {
        self.worker.get()
    }

    const SET_CREDIT_CHARGE_CMDS: &[Command] = &[
        Command::Read,
        Command::Write,
        Command::Ioctl,
        Command::QueryDirectory,
    ];

    const CREDIT_CALC_RATIO: u32 = 65536;

    #[maybe_async]
    async fn process_sequence_outgoing(&self, msg: &mut OutgoingMessage) -> crate::Result<()> {
        if let Some(neg) = self.negotiate_state() {
            if neg.selected_dialect > Dialect::Smb0202 && neg.global_caps.large_mtu() {
                if Self::SET_CREDIT_CHARGE_CMDS
                    .iter()
                    .any(|&cmd| cmd == msg.message.header.command)
                {
                    let send_payload_size = msg.message.content.req_payload_size();
                    let expected_response_payload_size = msg.message.content.expected_resp_size();
                    msg.message.header.credit_charge = (1
                        + (max(send_payload_size, expected_response_payload_size) - 1)
                            / Self::CREDIT_CALC_RATIO)
                        .try_into()
                        .unwrap();
                } else {
                    msg.message.header.credit_charge = 1;
                }
                let mut sequence_state = self.sequence_state.lock().await?;
                // Make sure that we have enough credits to satisfy this request:
                if sequence_state.curr_credits < msg.message.header.credit_charge {
                    // TODO: Consider waiting here if possible?
                    return Err(Error::NoCredits(
                        msg.message.header.credit_charge,
                        sequence_state.curr_credits,
                    ));
                }
                msg.message.header.credit_request = msg.message.header.credit_charge;
                // Request additional credits if required: if balance < extra, add to request the diff:
                if sequence_state.curr_credits < self.extra_credits_to_request {
                    msg.message.header.credit_request +=
                        self.extra_credits_to_request - sequence_state.curr_credits;
                }
                // Next Message ID should be incremented by the charge amount:
                msg.message.header.message_id = sequence_state.curr_msg_id;
                sequence_state.curr_msg_id += msg.message.header.credit_charge as u64;
                return Ok(());
            } else {
                debug_assert_eq!(msg.message.header.credit_request, 0);
                debug_assert_eq!(msg.message.header.credit_charge, 0);
            }
        }
        // Default case: next sequence ID
        {
            let mut sequence_state = self.sequence_state.lock().await?;
            msg.message.header.message_id = sequence_state.curr_msg_id;
            sequence_state.curr_msg_id += 1;
        }
        Ok(())
    }

    #[maybe_async]
    async fn process_sequence_incoming(&self, msg: &IncomingMessage) -> crate::Result<()> {
        if let Some(neg) = self.negotiate_state() {
            if neg.selected_dialect > Dialect::Smb0202 && neg.global_caps.large_mtu() {
                let mut sequence_state = self.sequence_state.lock().await?;
                sequence_state.curr_credits +=
                    msg.message.header.credit_request - msg.message.header.credit_charge;
            }
        }
        Ok(())
    }
}

impl MessageHandler for ConnectionMessageHandler {
    #[maybe_async]
    async fn sendo(&self, mut msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        // TODO: Add assertion in the struct regarding the selected dialect!
        let priority_value = match self.negotiate_state.get() {
            Some(negotiate_state) => match negotiate_state.selected_dialect {
                Dialect::Smb0311 => 1,
                _ => 0,
            },
            None => 0,
        };
        msg.message.header.flags = msg.message.header.flags.with_priority_mask(priority_value);
        self.process_sequence_outgoing(&mut msg).await?;

        Ok(self
            .worker
            .get()
            .ok_or(Error::InvalidState("Worker is uninitialized".into()))?
            .send(msg)
            .await?)
    }

    #[maybe_async]
    async fn recvo(&self, options: ReceiveOptions) -> crate::Result<IncomingMessage> {
        let msg = self
            .worker
            .get()
            .unwrap()
            .receive(options.msg_id_filter)
            .await?;

        // Command matching (if needed).
        if let Some(cmd) = options.cmd {
            if msg.message.header.command != cmd {
                return Err(Error::UnexpectedCommand(msg.message.header.command));
            }
        }

        // Direction matching.
        if !msg.message.header.flags.server_to_redir() {
            return Err(Error::InvalidMessage(
                "Expected server-to-redir message".into(),
            ));
        }

        // Expected status matching.
        if msg.message.header.status != options.status {
            // Return error only if it is unexpected.
            if let Content::ErrorResponse(error_res) = msg.message.content {
                return Err(Error::RecievedErrorMessage(error_res));
            }
            return Err(Error::UnexpectedMessageStatus(msg.message.header.status));
        }

        self.process_sequence_incoming(&msg).await?;

        Ok(msg)
    }
}
