//! SMB Session logic module.
//!
//! This module contains the session setup logic, as well as the session message handling,
//! including encryption and signing of messages.

use crate::connection::connection_info::ConnectionInfo;
use crate::connection::preauth_hash::PreauthHashState;
use crate::connection::worker::Worker;
use crate::sync_helpers::*;
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
use binrw::prelude::*;
use maybe_async::*;
use smb_msg::{Notification, ResponseContent, Status, session_setup::*};
use sspi::{AuthIdentity, Secret, Username};
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
type Upstream = HandlerReference<ConnectionMessageHandler>;

mod authenticator;
mod encryptor_decryptor;
mod signer;
mod sspi_network_client;
mod state;

use authenticator::{AuthenticationStep, Authenticator};
pub use encryptor_decryptor::{MessageDecryptor, MessageEncryptor};
pub use signer::MessageSigner;
pub use state::SessionInfo;

pub struct Session {
    pub(crate) handler: HandlerReference<SessionMessageHandler>,
    conn_info: Arc<ConnectionInfo>,
}

impl Session {
    /// Sets up the session with the specified username and password.
    #[maybe_async]
    pub(crate) async fn setup(
        user_name: &str,
        password: String,
        upstream: &Upstream,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Session> {
        let req_security_mode = SessionSecurityMode::new().with_signing_enabled(true);

        log::debug!("Setting up session for user {user_name}.");

        let username = Username::parse(user_name).map_err(|e| Error::SspiError(e.into()))?;
        let identity = AuthIdentity {
            username,
            password: Secret::new(password),
        };
        // Build the authenticator.
        let mut authenticator = Authenticator::build(identity, conn_info)?;
        let next_buf = match authenticator
            .next(&conn_info.negotiation.auth_buffer)
            .await?
        {
            AuthenticationStep::NextToken(buf) => buf,
            AuthenticationStep::Complete => {
                return Err(Error::InvalidState(
                    "Authentication completed before session setup.".to_string(),
                ));
            }
        };
        let request = OutgoingMessage::new(
            SessionSetupRequest::new(next_buf, req_security_mode, SetupRequestFlags::new()).into(),
        )
        .with_return_raw_data(true);

        // response hash is processed later, in the loop.
        let (send_result, init_response) = upstream
            .sendor_recvo(
                request,
                ReceiveOptions::new()
                    .with_status(&[Status::MoreProcessingRequired, Status::Success]),
            )
            .await?;

        let session_id = init_response.message.header.session_id;
        // Construct info object and handler.
        let session_state = Arc::new(Mutex::new(SessionInfo::new(session_id)));
        let handler = SessionMessageHandler::new(session_id, upstream, session_state.clone());

        // Update preauth hash
        let session_preauth_hash = conn_info
            .preauth_hash
            .clone()
            .next(&send_result.raw.unwrap())
            .next(&init_response.raw);

        let setup_result = if init_response.message.header.status == Status::Success as u32 {
            unimplemented!()
        } else {
            Self::_setup_more_processing(
                &mut authenticator,
                init_response.message.content.to_sessionsetup()?,
                &session_state,
                req_security_mode,
                &handler,
                conn_info,
                session_preauth_hash,
                false, // not binding to existing session
            )
            .await
        };

        let flags = match setup_result {
            Ok(flags) => flags,
            Err(e) => {
                // Notify the worker that the session is invalid.
                if let Err(x) = upstream
                    .worker()
                    .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
                    .session_ended(handler.session_id)
                    .await
                {
                    log::debug!("Failed to notify worker about session end: {x}!");
                }
                return Err(e);
            }
        };

        session_state.lock().await?.ready(flags, conn_info, None)?;

        log::info!("Session setup complete.");
        if flags.is_guest_or_null_session() {
            log::info!("Session is guest/anonymous.");
        }

        let session = Session {
            handler,
            conn_info: conn_info.clone(),
        };

        Ok(session)
    }

    #[maybe_async]
    async fn _setup_more_processing(
        authenticator: &mut Authenticator,
        init_response: SessionSetupResponse,
        session_state: &Arc<Mutex<SessionInfo>>,
        req_security_mode: SessionSecurityMode,
        handler: &HandlerReference<SessionMessageHandler>,
        conn_info: &Arc<ConnectionInfo>,
        mut preauth_hash: PreauthHashState,
        binding: bool,
    ) -> crate::Result<SessionFlags> {
        let mut last_setup_response = Some(init_response);
        let mut flags = None;

        // While there's a response to process, do so.
        while !authenticator.is_authenticated()? {
            let next_buf = match last_setup_response.as_ref() {
                Some(response) => authenticator.next(&response.buffer).await?,
                None => authenticator.next(&[]).await?,
            };
            let is_auth_done = authenticator.is_authenticated()?;

            last_setup_response = match next_buf {
                AuthenticationStep::NextToken(next_buf) => {
                    // We'd like to update preauth hash with the last request before accept.
                    // therefore we update it here for the PREVIOUS repsponse, assuming that we get an empty request when done.
                    let request = OutgoingMessage::new(
                        SessionSetupRequest::new(
                            next_buf,
                            req_security_mode,
                            SetupRequestFlags::new().with_binding(binding),
                        )
                        .into(),
                    )
                    .with_return_raw_data(true);
                    let send_result = handler.sendo(request).await?;

                    preauth_hash = preauth_hash.next(&send_result.raw.unwrap());

                    // If keys are exchanged, set them up, to enable validation of next response!

                    if is_auth_done {
                        let session_key: KeyToDerive = authenticator.session_key()?;
                        preauth_hash = preauth_hash.finish();

                        session_state.lock().await?.setup(
                            &session_key,
                            &preauth_hash.unwrap_final_hash().copied(),
                            conn_info,
                        )?;
                        log::trace!("Session keys are set.");

                        let worker = handler.upstream.handler.worker().ok_or_else(|| {
                            Error::InvalidState("Worker not available!".to_string())
                        })?;

                        if binding {
                            log::trace!(
                                "Binding to existing session, notifying worker that primary session shall be replaced."
                            );
                            worker.session_ended(handler.session_id).await?;
                        }
                        worker.session_started(session_state.clone()).await?;
                        log::trace!("Session inserted into worker.");
                    }

                    let expected_status = if is_auth_done {
                        Status::Success
                    } else {
                        Status::MoreProcessingRequired
                    };

                    let skip_security_validation = !is_auth_done;
                    let response = handler
                        .recvo_internal(
                            ReceiveOptions::new()
                                .with_status(&[expected_status])
                                .with_msg_id_filter(send_result.msg_id),
                            skip_security_validation,
                        )
                        .await?;

                    let message_form = response.form;
                    let session_setup_response = response.message.content.to_sessionsetup()?;

                    if is_auth_done {
                        // Important: If we did NOT make sure the message's signature is valid,
                        // we should do it now, as long as the session is not anonymous or guest.
                        if !session_setup_response
                            .session_flags
                            .is_guest_or_null_session()
                            && !message_form.signed_or_encrypted()
                        {
                            return Err(Error::InvalidMessage(
                                "Expected a signed message!".to_string(),
                            ));
                        }
                    } else {
                        preauth_hash = preauth_hash.next(&response.raw);
                    }

                    flags = Some(session_setup_response.session_flags);
                    Some(session_setup_response)
                }
                AuthenticationStep::Complete => None,
            };
        }

        flags.ok_or(Error::InvalidState(
            "Failed to complete authentication properly.".to_string(),
        ))
    }

    #[maybe_async]
    pub(crate) async fn bind(
        primary: &Session,
        handler: &HandlerReference<ConnectionMessageHandler>,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Session> {
        if primary.conn_info.negotiation.dialect_rev != conn_info.negotiation.dialect_rev {
            return Err(Error::InvalidState(
                "Cannot bind session to connection with different dialect.".to_string(),
            ));
        }
        if primary.conn_info.client_guid != conn_info.client_guid {
            return Err(Error::InvalidState(
                "Cannot bind session to connection with different client GUID.".to_string(),
            ));
        }
        let primary_session_state = primary.handler.session_state.lock().await?;
        if !primary_session_state.is_ready() {
            return Err(Error::InvalidState(
                "Cannot bind session that is not ready.".to_string(),
            ));
        }
        if primary_session_state.allow_unsigned()? {
            return Err(Error::InvalidState(
                "Cannot bind session that allows unsigned messages.".to_string(),
            ));
        }

        let primary_session_state_copy = Arc::new(Mutex::new((*primary_session_state).clone()));

        let identity = AuthIdentity {
            username: Username::new("LocalAdmin", None).unwrap(),
            password: "123456".to_string().into(),
        };
        let mut authenticator = Authenticator::build(identity, conn_info)?;
        let next_buf = match authenticator
            .next(&conn_info.negotiation.auth_buffer)
            .await?
        {
            AuthenticationStep::NextToken(buf) => buf,
            AuthenticationStep::Complete => {
                return Err(Error::InvalidState(
                    "Authentication completed before session setup.".to_string(),
                ));
            }
        };

        let security_mode = SessionSecurityMode::new().with_signing_enabled(true);

        let mut rebind_setup_request = OutgoingMessage::new(
            SessionSetupRequest::new(
                next_buf,
                security_mode,
                SetupRequestFlags::new().with_binding(true),
            )
            .into(),
        )
        .with_return_raw_data(true);

        let session_id = primary_session_state.id();
        rebind_setup_request.message.header.session_id = session_id;
        rebind_setup_request.message.header.flags.set_signed(true);
        drop(primary_session_state);

        let new_handler =
            SessionMessageHandler::new(session_id, handler, primary.handler.session_state.clone());

        new_handler
            .upstream
            .handler
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_started(primary_session_state_copy)
            .await?;

        let (send_result, rebind_response) = new_handler
            .sendor_recvo(
                rebind_setup_request,
                ReceiveOptions::new()
                    .with_status(&[Status::MoreProcessingRequired, Status::Success]),
            )
            .await?;

        let preauth_hash = conn_info
            .preauth_hash
            .clone()
            .next(&send_result.raw.unwrap())
            .next(&rebind_response.raw);

        let new_session = Arc::new(Mutex::new(SessionInfo::new(
            rebind_response.message.header.session_id,
        )));

        let rebind_response = rebind_response.message.content.to_sessionsetup()?;

        let flags = Session::_setup_more_processing(
            &mut authenticator,
            rebind_response,
            &new_session,
            security_mode,
            &new_handler,
            conn_info,
            preauth_hash,
            true, // binding to existing session
        )
        .await?;

        let primary_session_state = primary.handler.session_state.lock().await?;
        let primary_session_state_as_ref = primary_session_state.deref();
        new_session
            .lock()
            .await?
            .ready(flags, conn_info, Some(primary_session_state_as_ref))?;

        return Ok(Self {
            handler: new_handler,
            conn_info: conn_info.clone(),
        });
    }

    /// Connects to the specified tree using the current session.
    /// ## Arguments
    /// * `name` - The name of the tree to connect to. This should be a UNC path, with only server and share,
    ///     for example, `\\server\share`.
    #[maybe_async]
    pub async fn tree_connect(&self, name: &str) -> crate::Result<Tree> {
        let tree = Tree::connect(name, &self.handler, &self.conn_info).await?;
        Ok(tree)
    }

    /// Returns the Session ID of this session.
    ///
    /// This ID is the same as the SMB's session id,
    /// so it is unique-per-connection, and may be seen on the wire as well.
    #[inline]
    pub fn session_id(&self) -> u64 {
        self.handler.session_id
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

pub struct SessionMessageHandler {
    session_id: u64,
    upstream: Upstream,

    session_state: Arc<Mutex<SessionInfo>>,

    dropping: AtomicBool,
}

impl SessionMessageHandler {
    fn new(
        session_id: u64,
        upstream: &Upstream,
        session_state: Arc<Mutex<SessionInfo>>,
    ) -> HandlerReference<SessionMessageHandler> {
        HandlerReference::new(SessionMessageHandler {
            session_id,
            upstream: upstream.clone(),
            session_state,
            dropping: AtomicBool::new(false),
        })
    }

    #[maybe_async]
    async fn logoff(&self) -> crate::Result<()> {
        if self
            .dropping
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }

        {
            let state = self.session_state.lock().await?;
            if !state.is_ready() {
                log::trace!("Session not ready, or logged-off already, skipping logoff.");
                return Ok(());
            }
        }

        log::debug!("Logging off session.");

        let _response = self.send_recv(LogoffRequest {}.into()).await?;

        // This also invalidates the session object.
        log::info!("Session logged off.");

        Ok(())
    }

    /// (Internal)
    ///
    /// Assures the sessions may not be used anymore.
    #[maybe_async]
    async fn _invalidate(&self) -> crate::Result<()> {
        self.upstream
            .handler
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(self.session_id)
            .await
    }

    /// Logs off the session and invalidates it.
    ///
    /// # Notes
    /// This method waits for the logoff response to be received from the server.
    /// It is used when dropping the session.
    #[cfg(feature = "async")]
    #[maybe_async]
    async fn logoff_async(&self) {
        self.logoff().await.unwrap_or_else(|e| {
            log::error!("Failed to logoff: {e}");
        });
    }

    /// (Internal)
    ///
    /// # Returns
    /// whether allowing unsigned incoming messages is okay for this session.
    /// * If the session is ready, it checks whether signing is required by session flags.
    /// * If the session is being set up, it allows unsigned messages if allowed in the configuration.
    #[maybe_async]
    #[inline]
    async fn _is_incoming_unsigned_allowed(&self) -> crate::Result<bool> {
        let session = self.session_state.lock().await?;
        session.allow_unsigned()
    }

    /// (Internal)
    ///
    /// # Returns
    /// whether incoming messages encryption should be enforced for this session.
    #[maybe_async]
    #[inline]
    async fn _is_incoming_encrypted_required(&self) -> crate::Result<bool> {
        let session = self.session_state.lock().await?;
        Ok(session.is_ready() && session.should_encrypt()?)
    }

    /// (Internal)
    ///
    /// Verifies an [`IncomingMessage`] for the current session.
    /// This is trustworthy only since we trust the [`Transformer`][crate::connection::transformer::Transformer] implementation
    /// to provide the correct IDs and verify signatures and encryption.
    ///
    /// # Arguments
    /// * `incoming` - The incoming message to verify.
    /// # Returns
    /// An empty [`crate::Result`] if the message is valid, or an error if the message is invalid.
    #[maybe_async]
    async fn _verify_incoming(&self, incoming: &IncomingMessage) -> crate::Result<()> {
        // allow unsigned messages only if the session is anonymous or guest.
        // this is enforced against configuration when setting up the session.
        let unsigned_allowed = self._is_incoming_unsigned_allowed().await?;
        let encryption_required = self._is_incoming_encrypted_required().await?;

        // Make sure that it's our session.
        if incoming.message.header.session_id == 0 {
            return Err(Error::InvalidMessage(
                "No session ID in message that got to session!".to_string(),
            ));
        }
        if incoming.message.header.session_id != self.session_id {
            return Err(Error::InvalidMessage(
                "Message not for this session!".to_string(),
            ));
        }
        // Make sure encryption is used when required.
        if !incoming.form.encrypted && encryption_required {
            return Err(Error::InvalidMessage(
                "Message not encrypted, but encryption is required for the session!".to_string(),
            ));
        }
        // and signed, unless allowed not to.
        if !incoming.form.signed_or_encrypted() && !unsigned_allowed {
            return Err(Error::InvalidMessage(
                "Message not signed or encrypted, but signing is required for the session!"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// **Insecure! Insecure! Insecure!**
    ///
    /// Same as [`SessionMessageHandler::recvo`], but possible skips security validation.
    /// # Arguments
    /// * `options` - The options for receiving the message.
    /// * `skip_security_validation` - Whether to skip security validation of the incoming message.
    ///   This shall only be used when authentication is still being set up.
    /// # Returns
    /// An [`IncomingMessage`] if the message is valid, or an error if the message is invalid.
    #[maybe_async]
    async fn recvo_internal(
        &self,
        options: ReceiveOptions<'_>,
        skip_security_validation: bool,
    ) -> crate::Result<IncomingMessage> {
        let incoming = self.upstream.recvo(options).await?;

        if !skip_security_validation {
            self._verify_incoming(&incoming).await?;
        } else {
            // Note: this is performed here for extra security,
            // while we could have just checked the session state, let's require
            // the caller to explicitly state that it is okay to skip security validation.
            let session = self.session_state.lock().await?;
            assert!(session.is_initial());
        }

        Ok(incoming)
    }
}

impl MessageHandler for SessionMessageHandler {
    #[maybe_async]
    async fn sendo(&self, mut msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        {
            let session = self.session_state.lock().await?;
            if session.is_invalid() {
                return Err(Error::InvalidState("Session is invalid".to_string()));
            }

            // It is possible for a lower level to request encryption.
            if msg.encrypt {
                // Session must be ready to encrypt messages.
                if !session.is_ready() {
                    return Err(Error::InvalidState(
                        "Session is not ready, cannot encrypt message".to_string(),
                    ));
                }
            }
            // Otherwise, we should check the session's configuration.
            else if session.is_ready() || session.is_setting_up() {
                // Encrypt if configured for the session,
                if session.is_ready() && session.should_encrypt()? {
                    msg.encrypt = true;
                }
                // Sign
                else if !session.allow_unsigned()? {
                    msg.message.header.flags.set_signed(true);
                }
                // TODO: Re-check against config whether it's allowed to send/receive unsigned messages?
            }
        }
        msg.message.header.session_id = self.session_id;
        self.upstream.sendo(msg).await
    }

    #[maybe_async]
    async fn recvo(&self, options: ReceiveOptions<'_>) -> crate::Result<IncomingMessage> {
        let incoming = self.upstream.recvo(options).await?;

        self._verify_incoming(&incoming).await?;

        Ok(incoming)
    }

    #[maybe_async]
    async fn notify(&self, msg: IncomingMessage) -> crate::Result<()> {
        self._verify_incoming(&msg).await?;

        match &msg.message.content {
            ResponseContent::ServerToClientNotification(s2c_notification) => {
                match s2c_notification.notification {
                    Notification::NotifySessionClosed(_) => self._invalidate().await,
                }
            }
            _ => {
                log::warn!(
                    "Received unexpected message in session handler: {:?}",
                    msg.message.content
                );
                Ok(())
            }
        }
    }
}

#[cfg(not(feature = "async"))]
impl Drop for SessionMessageHandler {
    fn drop(&mut self) {
        self.logoff().unwrap_or_else(|e| {
            log::error!("Failed to logoff: {e}",);
        });
    }
}

#[cfg(feature = "async")]
impl Drop for SessionMessageHandler {
    fn drop(&mut self) {
        if self
            .dropping
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }

        let session_id = self.session_id;
        let upstream = self.upstream.clone();
        let session_state = self.session_state.clone();
        tokio::task::spawn(async move {
            let temp_handler = SessionMessageHandler {
                session_id,
                upstream,
                session_state,
                dropping: AtomicBool::new(false),
            };
            temp_handler.logoff_async().await;
        });
    }
}
