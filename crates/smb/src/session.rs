//! SMB Session logic module.
//!
//! This module contains the session setup logic, as well as the session message handling,
//! including encryption and signing of messages.

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
    tree::Tree,
};
use crate::{UncPath, sync_helpers::*};
use binrw::prelude::*;
use maybe_async::*;
use smb_msg::{Notification, ResponseContent, Status, session_setup::*};
use smb_transport::IoVec;
use sspi::{AuthIdentity, Secret, Username};
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
type Upstream = HandlerReference<ConnectionMessageHandler>;

mod authenticator;
mod channel;
mod encryptor_decryptor;
mod setup;
mod signer;
mod sspi_network_client;
mod state;

use authenticator::{AuthenticationStep, Authenticator};
pub use channel::*;
pub use encryptor_decryptor::{MessageDecryptor, MessageEncryptor};
pub use signer::MessageSigner;
pub use state::{ChannelInfo, SessionInfo};

use setup::*;

pub struct Session {
    channel: Channel,
}

pub struct Channel {
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
        user_name: &str,
        password: String,
        upstream: &Upstream,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Session> {
        let setup_result =
            SessionSetup::<SmbSessionNew>::new(user_name, password, upstream, conn_info, None)
                .await?;

        let channel = Self::_common_setup(setup_result).await?;

        Ok(Session { channel })
    }

    /// Binds an existing session to a new connection.
    ///
    /// Returns the new channel created on the new connection.
    #[maybe_async]
    pub(crate) async fn bind(
        &self,
        user_name: &str,
        password: String,
        handler: &HandlerReference<ConnectionMessageHandler>,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Channel> {
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
            user_name,
            password,
            handler,
            conn_info,
            Some(&self.handler.session_state()),
        )
        .await?;

        let channel = Self::_common_setup(setup_result).await?;

        Ok(channel)
    }

    async fn _common_setup<T>(mut session_setup: SessionSetup<'_, T>) -> crate::Result<Channel>
    where
        T: SessionSetupProperties,
    {
        let setup_result = session_setup.setup().await?;
        let session_id = {
            let session = setup_result.lock().await?;
            let session = session.session.lock().await?;
            log::info!("Session setup complete.");
            if session.allow_unsigned()? {
                log::info!("Session is guest/anonymous.");
            }

            session.id()
        };
        let handler =
            ChannelMessageHandler::new(session_id, true, session_setup.upstream(), &setup_result);

        let channel = Channel {
            handler,
            conn_info: session_setup.conn_info().clone(),
        };

        Ok(channel)
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
        &self.channel
    }
}

impl Channel {
    /// Connects to the specified tree on the current session.
    /// ## Arguments
    /// * `name` - The name of the tree to connect to.
    #[maybe_async]
    pub async fn tree_connect(&self, name: &UncPath) -> crate::Result<Tree> {
        let name = name.clone().with_no_path().to_string();
        let tree = Tree::connect(&name, &self.handler, &self.conn_info).await?;
        Ok(tree)
    }

    /// Returns the Session ID of this session.
    ///
    /// This ID is the same as the SMB's session id,
    /// so it is unique-per-connection, and may be seen on the wire as well.
    #[inline]
    pub fn session_id(&self) -> u64 {
        self.handler.session_id()
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
