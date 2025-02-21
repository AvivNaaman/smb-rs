//! SMB Session logic module.
//!
//! This module contains the session setup logic, as well as the session message handling,
//! including encryption and signing of messages.

use crate::connection::worker::Worker;
use crate::sync_helpers::*;
use crate::{
    connection::{preauth_hash::PreauthHashValue, ConnectionMessageHandler},
    crypto::KeyToDerive,
    msg_handler::{
        HandlerReference, IncomingMessage, MessageHandler, OutgoingMessage, ReceiveOptions,
        SendMessageResult,
    },
    packets::smb2::*,
    tree::Tree,
    Error,
};
use binrw::prelude::*;
use maybe_async::*;
use sspi::{AuthIdentity, Secret, Username};
use std::sync::Arc;
type UpstreamHandlerRef = HandlerReference<ConnectionMessageHandler>;

mod authenticator;
mod encryptor_decryptor;
mod signer;
mod state;

use authenticator::GssAuthenticator;
pub use encryptor_decryptor::{MessageDecryptor, MessageEncryptor};
pub use signer::MessageSigner;
pub use state::SessionState;

pub struct Session {
    handler: HandlerReference<SessionMessageHandler>,
    session_state: Arc<Mutex<SessionState>>,
}

impl Session {
    pub fn new(upstream: UpstreamHandlerRef) -> Session {
        let session_state = Arc::new(Mutex::new(SessionState::default()));
        Session {
            handler: SessionMessageHandler::new(upstream, session_state.clone()),
            session_state: session_state,
        }
    }

    /// Sets up the session with the specified username and password.
    #[maybe_async]
    pub async fn setup(&mut self, user_name: String, password: String) -> crate::Result<()> {
        if *self.handler.session_id.read().await? != 0 {
            return Err(Error::InvalidState("Session already set up!".to_string()));
        }

        log::debug!("Setting up session for user {}.", user_name);

        let username = Username::new(&user_name, Some("WORKGROUP")).map_err(|e| {
            Error::UsernameError(format!("Failed to create username: {}", e.to_string()))
        })?;

        // Build the authenticator.
        let (mut authenticator, next_buf) = {
            let negotate_state = self.handler.upstream().negotiate_state().unwrap();
            let identity = AuthIdentity {
                username,
                password: Secret::new(password),
            };
            GssAuthenticator::build(negotate_state.gss_token(), identity)?
        };

        let request = OutgoingMessage::new(PlainMessage::new(Content::SessionSetupRequest(
            SessionSetupRequest::new(next_buf),
        )));

        // response hash is processed later, in the loop.
        let response = self
            .handler
            .upstream
            .sendo_recvo(
                request,
                ReceiveOptions::new().status(Status::MoreProcessingRequired),
            )
            .await?;

        // Set session id.
        *self.handler.session_id.write().await? = response.message.header.session_id;
        self.session_state.lock().await?.session_id = response.message.header.session_id;

        let mut response = Some(response);
        let mut flags = None;
        while !authenticator.is_authenticated()? {
            // If there's a response to process, do so.
            let last_setup_response = match response.as_ref() {
                Some(response) => Some(
                    match &response.message.content {
                        Content::SessionSetupResponse(response) => Some(response),
                        _ => None,
                    }
                    .unwrap(),
                ),
                None => None,
            };

            flags = match last_setup_response {
                Some(response) => Some(response.session_flags),
                None => flags,
            };

            let next_buf = match last_setup_response.as_ref() {
                Some(response) => authenticator.next(&response.buffer)?,
                None => authenticator.next(&vec![])?,
            };

            response = match next_buf {
                Some(next_buf) => {
                    // We'd like to update preauth hash with the last request before accept.
                    // therefore we update it here for the PREVIOUS repsponse, assuming that we get an empty request when done.
                    let mut request = OutgoingMessage::new(PlainMessage::new(
                        Content::SessionSetupRequest(SessionSetupRequest::new(next_buf)),
                    ));
                    let is_about_to_finish = authenticator.keys_exchanged()
                        && !SessionState::is_set_up(&self.session_state).await?;
                    request.finalize_preauth_hash = is_about_to_finish;
                    let result = self.handler.sendo(request).await?;

                    // If keys are exchanged, set them up, to enable validation of next response!
                    if is_about_to_finish {
                        let ntlm_key: KeyToDerive = authenticator.session_key()?;
                        self.key_setup(&ntlm_key, &result.preauth_hash.unwrap())
                            .await?;
                    }

                    let expected_status = if is_about_to_finish {
                        Status::Success
                    } else {
                        Status::MoreProcessingRequired
                    };
                    let response = self
                        .handler
                        .recvo(ReceiveOptions::new().status(expected_status).to(result))
                        .await?;
                    Some(response)
                }
                None => None,
            };
        }
        log::info!("Session setup complete.");
        // Setup is complete, session is now ready to use.
        SessionState::set_flags(&mut self.session_state, flags.unwrap()).await?;
        Ok(())
    }

    /// Sets up the session signing/encription keys.
    #[maybe_async]
    async fn key_setup(
        &mut self,
        exchanged_session_key: &KeyToDerive,
        preauth_hash: &PreauthHashValue,
    ) -> crate::Result<()> {
        let state = self.handler.upstream().negotiate_state().unwrap();
        SessionState::set(
            &mut self.session_state,
            exchanged_session_key,
            preauth_hash,
            state,
        )
        .await?;
        log::trace!("Session signing key set.");

        self.handler
            .upstream()
            .handler
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_started(self.session_state.clone())
            .await?;
        log::trace!("Session inserted into worker.");

        Ok(())
    }

    /// Connects to the specified tree using the current session.
    #[maybe_async]
    pub async fn tree_connect(&mut self, name: String) -> crate::Result<Tree> {
        let mut tree = Tree::new(name, self.handler.clone());
        tree.connect().await?;
        Ok(tree)
    }
}

pub struct SessionMessageHandler {
    session_id: RwLock<u64>,
    upstream: UpstreamHandlerRef,

    session_state: Arc<Mutex<SessionState>>,
}

impl SessionMessageHandler {
    pub fn new(
        upstream: UpstreamHandlerRef,
        session_state: Arc<Mutex<SessionState>>,
    ) -> HandlerReference<SessionMessageHandler> {
        HandlerReference::new(SessionMessageHandler {
            session_id: RwLock::new(0),
            upstream,
            session_state,
        })
    }

    #[maybe_async]
    pub async fn should_sign(&self) -> crate::Result<bool> {
        SessionState::signing_enabled(&self.session_state).await
    }

    #[maybe_async]
    pub async fn should_encrypt(&self) -> crate::Result<bool> {
        SessionState::encryption_enabled(&self.session_state).await
    }

    fn upstream(&self) -> &UpstreamHandlerRef {
        &self.upstream
    }

    #[maybe_async]
    async fn logoff(&self) -> crate::Result<()> {
        if *self.session_id.read().await? == 0 {
            log::trace!("Session not set up/already logged-off.");
            return Ok(());
        }

        log::debug!("Logging off session.");

        let _response = self
            .send_recv(Content::LogoffRequest(Default::default()))
            .await?;

        // Reset session ID and keys.
        SessionState::invalidate(&self.session_state).await?;
        let session_id = {
            let mut session_id_ref = self.session_id.write().await?;
            let session_id = *session_id_ref;
            *session_id_ref = 0;
            session_id
        };
        self.upstream()
            .handler
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(session_id)
            .await?;

        log::info!("Session logged off.");

        Ok(())
    }

    #[cfg(feature = "async")]
    #[maybe_async]
    pub async fn logoff_async(&mut self) {
        self.logoff().await.unwrap_or_else(|e| {
            log::error!("Failed to logoff: {}", e);
        });
    }
}

impl MessageHandler for SessionMessageHandler {
    #[maybe_async]
    async fn sendo(&self, mut msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        if *self.session_id.read().await? == 0 {
            return Err(
                Error::InvalidState("Session is invalid or not set up!".to_string()).into(),
            );
        }

        // Encrypt?
        if self.should_encrypt().await? {
            msg.encrypt = true;
        }
        // Sign instead?
        else if self.should_sign().await? {
            msg.message.header.flags.set_signed(true);
        }
        msg.message.header.session_id = *self.session_id.read().await?;
        self.upstream.sendo(msg).await
    }

    #[maybe_async]
    async fn recvo(
        &self,
        options: crate::msg_handler::ReceiveOptions,
    ) -> crate::Result<IncomingMessage> {
        if *self.session_id.read().await? == 0 {
            return Err(Error::InvalidState(
                "Session is invalid or not set up!".to_string(),
            ));
        }

        let incoming = self.upstream.recvo(options).await?;
        // Make sure that it's our session.
        if incoming.message.header.session_id == 0 {
            return Err(Error::InvalidMessage(
                "No session ID in message that got to session!".to_string(),
            ));
        } else if incoming.message.header.session_id != *self.session_id.read().await? {
            return Err(Error::InvalidMessage(
                "Message not for this session!".to_string(),
            ));
        } else if !incoming.form.signed && !incoming.form.encrypted {
            return Err(Error::InvalidMessage(
                "Message not signed or encrypted!".to_string(),
            ));
        }

        Ok(incoming)
    }
}

#[cfg(feature = "sync")]
impl Drop for SessionMessageHandler {
    fn drop(&mut self) {
        self.logoff().unwrap_or_else(|e| {
            log::error!("Failed to logoff: {}", e);
        });
    }
}

#[cfg(feature = "async")]
impl Drop for SessionMessageHandler {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.logoff_async().await;
            })
        })
    }
}
