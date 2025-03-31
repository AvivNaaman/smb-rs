pub mod config;
pub mod connection_info;
pub mod netbios_client;
#[cfg(not(feature = "single_threaded"))]
pub mod notification_handler;
pub mod preauth_hash;
pub mod transformer;
pub mod worker;

use crate::dialects::DialectImpl;
use crate::packets::guid::Guid;
use crate::packets::smb2::{Command, Message};
use crate::Error;
use crate::{compression, sync_helpers::*};
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
pub use config::*;
use connection_info::{ConnectionInfo, NegotiatedProperties};
use maybe_async::*;
use netbios_client::NetBiosClient;
#[cfg(not(feature = "single_threaded"))]
use notification_handler::NotificationHandler;
use rand::rngs::OsRng;
use rand::Rng;
use std::cmp::max;
use std::sync::atomic::{AtomicU16, AtomicU64};
use std::sync::Arc;
use std::time::Duration;
pub use transformer::TransformError;
use worker::{Worker, WorkerImpl};

pub struct Connection {
    handler: HandlerReference<ConnectionMessageHandler>,
    config: ConnectionConfig,
}

impl Connection {
    /// Creates a new SMB connection, specifying a server configuration, without connecting to a server.
    /// Use the [`connect`](Connection::connect) method to establish a connection.
    pub fn build(config: ConnectionConfig) -> crate::Result<Connection> {
        config.validate()?;
        let client_guid = config.client_guid.unwrap_or_else(Guid::gen);
        Ok(Connection {
            handler: HandlerReference::new(ConnectionMessageHandler::new(client_guid)),
            config,
        })
    }

    /// Sets operations timeout for the connection.
    #[maybe_async]
    pub async fn set_timeout(&mut self, timeout: Duration) -> crate::Result<()> {
        self.config.timeout = Some(timeout);
        if let Some(worker) = self.handler.worker.get() {
            worker.set_timeout(timeout).await?;
        }
        Ok(())
    }

    /// Connects to the specified server, if it is not already connected, and negotiates the connection.
    #[maybe_async]
    pub async fn connect(&mut self, address: &str) -> crate::Result<()> {
        if self.handler.worker().is_some() {
            return Err(Error::InvalidState("Already connected".into()));
        }

        let mut netbios_client = NetBiosClient::new(self.config.timeout());

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

    /// This method switches the netbios client to SMB2 and starts the worker.
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
            let response = netbios_client.receive_bytes().await?.parse_content()?;
            let message = match response {
                NetBiosMessageContent::SMB2Message(Message::Plain(m)) => m,
                _ => {
                    return Err(Error::InvalidMessage(
                        "Expected SMB2 negotiate response, got SMB1".to_string(),
                    ))
                }
            };

            let smb2_negotiate_response = message.content.to_negotiateresponse()?;

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

        Ok(WorkerImpl::start(netbios_client, self.config.timeout()).await?)
    }

    /// This method perofrms the SMB2 negotiation.
    #[maybe_async]
    async fn negotiate_smb2(&mut self) -> crate::Result<ConnectionInfo> {
        // Confirm that we're not already negotiated.
        if self.handler.conn_info.get().is_some() {
            return Err(Error::InvalidState("Already negotiated".into()));
        }

        log::debug!("Negotiating SMB2");

        // List possible versions to run with.
        let min_dialect = self.config.min_dialect.unwrap_or(Dialect::MIN);
        let max_dialect = self.config.max_dialect.unwrap_or(Dialect::MAX);
        let dialects: Vec<Dialect> = Dialect::ALL
            .iter()
            .filter(|dialect| **dialect >= min_dialect && **dialect <= max_dialect)
            .copied()
            .collect();

        if dialects.is_empty() {
            return Err(Error::InvalidConfiguration(
                "No dialects to negotiate".to_string(),
            ));
        }

        let encryption_algos = if !self.config.encryption_mode.is_disabled() {
            crypto::ENCRYPTING_ALGOS.into()
        } else {
            vec![]
        };

        // Send SMB2 negotiate request
        let response = self
            .handler
            .send_recv(Content::NegotiateRequest(self.make_smb2_neg_request(
                dialects,
                crypto::SIGNING_ALGOS.to_vec(),
                encryption_algos,
                compression::SUPPORTED_ALGORITHMS.to_vec(),
            )))
            .await?;

        let smb2_negotiate_response = response.message.content.to_negotiateresponse()?;

        // well, only 3.1 is supported for starters.
        let dialect_rev = smb2_negotiate_response.dialect_revision.try_into()?;
        if dialect_rev > max_dialect || dialect_rev < min_dialect {
            return Err(Error::NegotiationError(
                "Server selected an unsupported dialect.".into(),
            ));
        }

        let dialect_impl = DialectImpl::new(dialect_rev);
        let mut negotiation = NegotiatedProperties {
            server_guid: smb2_negotiate_response.server_guid,
            caps: smb2_negotiate_response.capabilities.clone(),
            max_transact_size: smb2_negotiate_response.max_transact_size,
            max_read_size: smb2_negotiate_response.max_read_size,
            max_write_size: smb2_negotiate_response.max_write_size,
            auth_buffer: smb2_negotiate_response.buffer.clone(),
            signing_algo: None,
            encryption_cipher: None,
            compression: None,
            dialect_rev,
        };

        dialect_impl.process_negotiate_request(
            &smb2_negotiate_response,
            &mut negotiation,
            &self.config,
        )?;
        if ((!u32::from_le_bytes(dialect_impl.get_negotiate_caps_mask().into_bytes()))
            & u32::from_le_bytes(negotiation.caps.into_bytes()))
            != 0
        {
            return Err(Error::NegotiationError(
                "Server capabilities are invalid for the selected dialect.".into(),
            ));
        }

        log::trace!(
            "Negotiated SMB results: dialect={:?}, state={:?}",
            dialect_rev,
            &negotiation
        );

        Ok(ConnectionInfo {
            negotiation,
            dialect: dialect_impl,
            config: self.config.clone(),
        })
    }

    /// Creates an SMB2 negotiate request.
    fn make_smb2_neg_request(
        &self,
        supported_dialects: Vec<Dialect>,
        signing_algorithms: Vec<SigningAlgorithmId>,
        encrypting_algorithms: Vec<EncryptionCipher>,
        compression_algorithms: Vec<CompressionAlgorithm>,
    ) -> NegotiateRequest {
        let client_guid = self.handler.client_guid;
        let client_netname = self
            .config
            .client_name
            .clone()
            .unwrap_or_else(|| "smb-client".to_string());
        let has_signing = signing_algorithms.len() > 0;
        let has_encryption = encrypting_algorithms.len() > 0;

        // Context list supported on SMB3.1.1+
        let ctx_list = if supported_dialects.contains(&Dialect::Smb0311) {
            let ctx_list = vec![
                NegotiateContext {
                    context_type: NegotiateContextType::PreauthIntegrityCapabilities,
                    data: NegotiateContextValue::PreauthIntegrityCapabilities(
                        PreauthIntegrityCapabilities {
                            hash_algorithms: vec![HashAlgorithm::Sha512],
                            salt: (0..32).map(|_| OsRng.gen()).collect(),
                        },
                    ),
                },
                NegotiateContext {
                    context_type: NegotiateContextType::NetnameNegotiateContextId,
                    data: NegotiateContextValue::NetnameNegotiateContextId(
                        NetnameNegotiateContextId {
                            netname: client_netname.into(),
                        },
                    ),
                },
                NegotiateContext {
                    context_type: NegotiateContextType::EncryptionCapabilities,
                    data: NegotiateContextValue::EncryptionCapabilities(EncryptionCapabilities {
                        ciphers: encrypting_algorithms,
                    }),
                },
                NegotiateContext {
                    context_type: NegotiateContextType::CompressionCapabilities,
                    data: NegotiateContextValue::CompressionCapabilities(CompressionCaps {
                        flags: CompressionCapsFlags::new()
                            .with_chained(compression_algorithms.len() > 0),
                        compression_algorithms,
                    }),
                },
                NegotiateContext {
                    context_type: NegotiateContextType::SigningCapabilities,
                    data: NegotiateContextValue::SigningCapabilities(SigningCapabilities {
                        signing_algorithms,
                    }),
                },
            ];
            Some(ctx_list)
        } else {
            None
        };

        // Set capabilities to 0 if no SMB3 dialects are supported.
        let capabilities = if supported_dialects.iter().all(|d| !d.is_smb3()) {
            GlobalCapabilities::new()
        } else {
            let capabilities = GlobalCapabilities::new()
                .with_dfs(true)
                .with_leasing(true)
                .with_large_mtu(true)
                .with_multi_channel(true)
                .with_persistent_handles(true)
                .with_directory_leasing(true);

            if has_encryption {
                capabilities.with_encryption(true);
            }

            // Enable notifications by client config + build config.
            if !self.config.disable_notifications
                && cfg!(not(feature = "single_threaded"))
                && supported_dialects.contains(&Dialect::Smb0311)
            {
                capabilities.with_notifications(true);
            }
            capabilities
        };

        let security_mode = NegotiateSecurityMode::new().with_signing_enabled(has_signing);

        NegotiateRequest {
            security_mode: security_mode,
            capabilities,
            client_guid,
            dialects: supported_dialects,
            negotiate_context_list: ctx_list,
        }
    }

    /// Send negotiate messages, potentially
    #[maybe_async]
    async fn negotiate(
        &mut self,
        netbios_client: NetBiosClient,
        multi_protocol: bool,
    ) -> crate::Result<()> {
        if self.handler.conn_info.get().is_some() {
            return Err(Error::InvalidState("Already negotiated".into()));
        }

        // Negotiate SMB1, Switch to SMB2
        let worker = self
            .negotiate_switch_to_smb2(netbios_client, multi_protocol)
            .await?;

        self.handler.worker.set(worker).unwrap();

        // Negotiate SMB2
        let info = self.negotiate_smb2().await?;

        self.handler
            .worker
            .get()
            .ok_or("Worker is uninitialized")
            .unwrap()
            .negotaite_complete(&info)
            .await;

        #[cfg(not(feature = "single_threaded"))]
        if !self.config.disable_notifications && info.negotiation.caps.notifications() {
            self.handler.start_notification_handler().await?;
        }

        self.handler.conn_info.set(Arc::new(info)).unwrap();

        log::info!("Negotiation successful");
        Ok(())
    }

    #[maybe_async]
    pub async fn authenticate(&self, user_name: &str, password: String) -> crate::Result<Session> {
        Session::setup(
            user_name,
            password,
            &self.handler,
            self.handler.conn_info.get().unwrap(),
        )
        .await
    }
}

/// This struct is the internal message handler for the SMB client.
pub struct ConnectionMessageHandler {
    client_guid: Guid,
    /// The number of extra credits to be requested by the client
    /// to enable larger requests/multiple outstanding requests.
    extra_credits_to_request: u16,

    worker: OnceCell<Arc<WorkerImpl>>,
    #[cfg(not(feature = "single_threaded"))]
    notification_handler: OnceCell<NotificationHandler>,

    // Negotiation-related state.
    conn_info: OnceCell<Arc<ConnectionInfo>>,

    /// Number of credits available to the client at the moment, for the next requests.
    curr_credits: Semaphore,
    /// The current message ID to be used in the next message.
    curr_msg_id: AtomicU64,
    /// The number of credits granted to the client by the server, including the being-used ones.
    credit_pool: AtomicU16,
}

impl ConnectionMessageHandler {
    fn new(client_guid: Guid) -> ConnectionMessageHandler {
        ConnectionMessageHandler {
            client_guid,
            worker: OnceCell::new(),
            conn_info: OnceCell::new(),
            extra_credits_to_request: 4,
            curr_credits: Semaphore::new(1),
            curr_msg_id: AtomicU64::new(1),
            credit_pool: AtomicU16::new(1),
            #[cfg(not(feature = "single_threaded"))]
            notification_handler: OnceCell::new(),
        }
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
        if let Some(neg) = self.conn_info.get() {
            if neg.negotiation.caps.large_mtu() {
                // Calculate the cost of the message (charge).
                let cost = if Self::SET_CREDIT_CHARGE_CMDS
                    .iter()
                    .any(|&cmd| cmd == msg.message.header.command)
                {
                    let send_payload_size = msg.message.content.req_payload_size();
                    let expected_response_payload_size = msg.message.content.expected_resp_size();
                    (1 + (max(send_payload_size, expected_response_payload_size) - 1)
                        / Self::CREDIT_CALC_RATIO)
                        .try_into()
                        .unwrap()
                } else {
                    1
                };

                // First, acquire credits from the semaphore, and forget them.
                // They may be returned via the response message, at `process_sequence_incoming` below.
                self.curr_credits.acquire_many(cost as u32).await?.forget();

                let mut request = cost;
                // Request additional credits if required: if balance < extra, add to request the diff:
                let current_pool_size = self.credit_pool.load(std::sync::atomic::Ordering::SeqCst);
                if current_pool_size < self.extra_credits_to_request {
                    request += self.extra_credits_to_request - current_pool_size;
                }

                msg.message.header.credit_charge = cost;
                msg.message.header.credit_request = request;
                msg.message.header.message_id = self
                    .curr_msg_id
                    .fetch_add(cost as u64, std::sync::atomic::Ordering::SeqCst);

                return Ok(());
            } else {
                debug_assert_eq!(msg.message.header.credit_request, 0);
                debug_assert_eq!(msg.message.header.credit_charge, 0);
            }
        }
        // Default case: next sequence ID
        {
            msg.message.header.message_id = self
                .curr_msg_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    #[maybe_async]
    async fn process_sequence_incoming(&self, msg: &IncomingMessage) -> crate::Result<()> {
        if let Some(neg) = self.conn_info.get() {
            if neg.negotiation.caps.large_mtu() {
                let granted_credits = msg.message.header.credit_request;
                let charged_credits = msg.message.header.credit_charge;
                // Update the pool size - return how many EXTRA credits were granted.
                // also, handle the case where the server granted less credits than charged.
                if charged_credits > granted_credits {
                    self.credit_pool.fetch_sub(
                        charged_credits - granted_credits,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                } else {
                    self.credit_pool.fetch_add(
                        granted_credits - charged_credits,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                }

                // Return the credits to the pool.
                self.curr_credits.add_permits(granted_credits as usize);
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "single_threaded"))]
    #[maybe_async]
    async fn start_notification_handler(&self) -> crate::Result<()> {
        let worker = self.worker.get().unwrap();
        let handler = NotificationHandler::start(worker)?;
        self.notification_handler
            .set(handler)
            .map_err(|_| Error::InvalidState("Notification handler already started".into()))?;
        Ok(())
    }
}

impl MessageHandler for ConnectionMessageHandler {
    #[maybe_async]
    async fn sendo(&self, mut msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        let priority_value = match self.conn_info.get() {
            Some(neg_info) => match neg_info.negotiation.dialect_rev {
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
    async fn recvo(&self, options: ReceiveOptions<'_>) -> crate::Result<IncomingMessage> {
        let msg = self.worker.get().unwrap().receive(&options).await?;

        // Command matching (if needed).
        if let Some(cmd) = options.cmd {
            if msg.message.header.command != cmd {
                return Err(Error::UnexpectedMessageCommand(msg.message.header.command));
            }
        }

        // Direction matching.
        if !msg.message.header.flags.server_to_redir() {
            return Err(Error::InvalidMessage(
                "Expected server-to-redir message".into(),
            ));
        }

        // Expected status matching. Error if no match.
        if !options
            .status
            .iter()
            .any(|s| msg.message.header.status == *s as u32)
        {
            if let Content::ErrorResponse(error_res) = msg.message.content {
                return Err(Error::ReceivedErrorMessage(
                    msg.message.header.status,
                    error_res,
                ));
            }
            return Err(Error::UnexpectedMessageStatus(msg.message.header.status));
        }

        self.process_sequence_incoming(&msg).await?;

        Ok(msg)
    }
}
