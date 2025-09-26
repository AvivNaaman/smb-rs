//! SMB Session logic module.
//!
//! This module contains the session setup logic, as well as the session message handling,
//! including encryption and signing of messages.

use crate::UncPath;
use crate::connection::connection_info::ConnectionInfo;
use crate::connection::preauth_hash::{PreauthHashState, PreauthHashValue};
use crate::connection::worker::Worker;
use crate::{
    Error,
    connection::ConnectionMessageHandler,
    crypto::KeyToDerive,
    msg_handler::{
        HandlerReference, IncomingMessage, MessageHandler, OutgoingMessage, ReceiveOptions,
        SendMessageResult,
    },
    sync_helpers::*,
    tree::Tree,
};
use smb_msg::{Notification, ResponseContent, Status, session_setup::*};
use smb_transport::IoVec;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU32};
type Upstream = HandlerReference<ConnectionMessageHandler>;

mod authenticator;
mod channel;
mod encryptor_decryptor;
mod setup;
mod signer;
mod sspi_network_client;
mod state;

pub use channel::*;
pub use encryptor_decryptor::{MessageDecryptor, MessageEncryptor};
pub use signer::MessageSigner;
pub use state::{ChannelInfo, SessionInfo};

use setup::*;

pub struct Session {
    primary_channel: Channel,
    alt_channels: RwLock<HashMap<u32, Channel>>,
    channel_counter: AtomicU32,

    // Message handler for this session.
    session_handler: HandlerReference<SessionMessageHandler>,
}

pub struct Channel {
    channel_id: u32,

    pub(crate) handler: HandlerReference<ChannelMessageHandler>,
    conn_info: Arc<ConnectionInfo>,
}

impl Session {
    /// Sets up a new session on the specified connection.
    /// This method is crate-internal; Use [`Connection::authenticate`] to create a new session.
    ///
    /// [Session::bind] may be used instead, to bind an existing session to a new connection.
    #[maybe_async]
    pub(crate) async fn create(
        identity: sspi::AuthIdentity,
        upstream: &Upstream,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Session> {
        let setup_result =
            SessionSetup::<SmbSessionNew>::new(identity, upstream, conn_info, None).await?;

        const FIRST_CHANNEL_ID: u32 = 0;
        let primary_channel = Self::_common_setup(setup_result, FIRST_CHANNEL_ID).await?;

        let handler =
            HandlerReference::new(SessionMessageHandler::new(primary_channel.handler.clone()));

        Ok(Session {
            session_handler: handler,
            primary_channel,
            alt_channels: Default::default(),
            channel_counter: AtomicU32::new(FIRST_CHANNEL_ID + 1),
        })
    }

    /// Binds an existing session to a new connection.
    ///
    /// Returns the channel ID (in the scope of the current session) of the newly created channel.
    #[maybe_async]
    pub(crate) async fn bind(
        &self,
        identity: sspi::AuthIdentity,
        handler: &HandlerReference<ConnectionMessageHandler>,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<u32> {
        if self.conn_info.negotiation.dialect_rev != conn_info.negotiation.dialect_rev {
            return Err(Error::InvalidState(
                "Cannot bind session to connection with different dialect.".to_string(),
            ));
        }
        if self.conn_info.client_guid != conn_info.client_guid {
            return Err(Error::InvalidState(
                "Cannot bind session to connection with different client GUID.".to_string(),
            ));
        }

        {
            let primary_session_state = self.handler.session_state().lock().await?;
            let session = primary_session_state.session.lock().await?;
            if !session.is_ready() {
                return Err(Error::InvalidState(
                    "Cannot bind session that is not ready.".to_string(),
                ));
            }
            if session.allow_unsigned()? {
                return Err(Error::InvalidState(
                    "Cannot bind session that allows unsigned messages.".to_string(),
                ));
            }
        }

        let setup_result = SessionSetup::<SmbSessionBind>::new(
            identity,
            handler,
            conn_info,
            Some(self.handler.session_state()),
        )
        .await?;

        let internal_channel_id = self
            .channel_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let channel = Self::_common_setup(setup_result, internal_channel_id).await?;

        self.alt_channels
            .write()
            .await?
            .insert(internal_channel_id, channel);

        self.session_handler.channel_handlers.write().await?.insert(
            internal_channel_id,
            self.alt_channels
                .read()
                .await?
                .get(&internal_channel_id)
                .unwrap()
                .handler
                .clone(),
        );

        Ok(internal_channel_id)
    }

    async fn _common_setup<T>(
        mut session_setup: SessionSetup<'_, T>,
        channel_id: u32,
    ) -> crate::Result<Channel>
    where
        T: SessionSetupProperties,
    {
        let setup_result = session_setup.setup().await?;
        let session_id = {
            let session = setup_result.lock().await?;
            let session = session.session.lock().await?;
            log::debug!("Session setup complete.");
            if session.allow_unsigned()? {
                log::debug!("Session is guest/anonymous.");
            }

            session.id()
        };
        let handler = ChannelMessageHandler::new(
            session_id,
            channel_id,
            true,
            session_setup.upstream(),
            &setup_result,
        );

        let channel = Channel {
            handler,
            channel_id,
            conn_info: session_setup.conn_info().clone(),
        };

        Ok(channel)
    }

    /// Connects to the specified tree on the current session.
    /// ## Arguments
    /// * `name` - The name of the tree to connect to.
    #[maybe_async]
    pub async fn tree_connect(&self, name: &UncPath) -> crate::Result<Tree> {
        let name = name.clone().with_no_path().to_string();
        let tree = Tree::connect(&name, &self.session_handler, &self.conn_info).await?;
        Ok(tree)
    }

    /// Logs off the session.
    ///
    /// Any resources held by the session will be released,
    /// and any [`Tree`] objects and their resources will be unusable.
    #[maybe_async]
    pub async fn close(&self) -> crate::Result<()> {
        self.handler.logoff().await
    }
}

impl Deref for Session {
    type Target = Channel;

    fn deref(&self) -> &Self::Target {
        &self.primary_channel
    }
}

impl Channel {
    /// Returns the Session ID of this session.
    ///
    /// This ID is the same as the SMB's session id,
    /// so it is unique-per-connection, and may be seen on the wire as well.
    #[inline]
    pub fn session_id(&self) -> u64 {
        self.handler.session_id()
    }

    #[inline]
    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }
}

#[derive(Clone)]
pub struct SessionAndChannel {
    pub session_id: u64,

    pub session: Arc<Mutex<SessionInfo>>,
    pub channel: Option<ChannelInfo>,
}

impl SessionAndChannel {
    pub fn new(session_id: u64, session: Arc<Mutex<SessionInfo>>) -> Self {
        Self {
            session_id,
            session,
            channel: None,
        }
    }

    pub fn set_channel(&mut self, channel: ChannelInfo) {
        self.channel = Some(channel);
    }
}

pub(crate) struct SessionMessageHandler {
    session_id: u64,
    // this is used to speed up access to the primary channel handler.
    primary_channel_id: u32,
    primary_channel: HandlerReference<ChannelMessageHandler>,

    channel_handlers: RwLock<HashMap<u32, HandlerReference<ChannelMessageHandler>>>,
}

impl SessionMessageHandler {
    pub fn new(primary_channel: HandlerReference<ChannelMessageHandler>) -> Self {
        let session_id = primary_channel.session_id();
        let primary_channel_id = primary_channel.channel_id();
        Self {
            session_id,
            primary_channel_id,
            primary_channel: primary_channel.clone(),
            channel_handlers: RwLock::new(HashMap::from([(primary_channel_id, primary_channel)])),
        }
    }
}

impl MessageHandler for SessionMessageHandler {
    async fn sendo(&self, msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        match msg.channel_id {
            Some(channel_id) => {
                if let Some(handler) = self.channel_handlers.read().await?.get(&channel_id) {
                    handler.sendo(msg).await
                } else {
                    Err(Error::ChannelNotFound(self.session_id, channel_id))
                }
            }
            None => self.primary_channel.sendo(msg).await,
        }
    }

    async fn recvo(&self, options: ReceiveOptions<'_>) -> crate::Result<IncomingMessage> {
        match options.channel_id {
            Some(channel_id) => {
                if let Some(handler) = self.channel_handlers.read().await?.get(&channel_id) {
                    handler.recvo(options).await
                } else {
                    Err(Error::ChannelNotFound(self.session_id, channel_id))
                }
            }
            None => self.primary_channel.recvo(options).await,
        }
    }
}
