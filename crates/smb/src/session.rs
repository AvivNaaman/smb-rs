//! SMB Session logic module.
//!
//! This module contains the session setup logic, as well as the session message handling,
//! including encryption and signing of messages.

use crate::connection::connection_info::ConnectionInfo;
use crate::connection::preauth_hash::{PreauthHashState, PreauthHashValue};
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
use smb_transport::IoVec;
use sspi::{AuthIdentity, Secret, Username};
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
pub use state::{ChannelInfo, SessionInfo};

pub struct Session {
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
                .await?
                .setup()
                .await?;
        let session_id = {
            let session = setup_result.lock().await?;
            let session = session.session.lock().await?;
            log::info!("Session setup complete.");
            if session.allow_unsigned()? {
                log::info!("Session is guest/anonymous.");
            }

            session.id()
        };
        let handler = ChannelMessageHandler::new(session_id, true, upstream, &setup_result);

        let session = Session {
            handler,
            conn_info: conn_info.clone(),
        };

        Ok(session)
    }

    #[maybe_async]
    pub(crate) async fn bind(
        self: &Session,
        user_name: &str,
        password: String,
        handler: &HandlerReference<ConnectionMessageHandler>,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<()> {
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
            let primary_session_state = self.handler.session_state.lock().await?;
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
            Some(&self.handler.session_state),
        )
        .await?
        .setup()
        .await?;
        Ok(())
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

struct SessionSetup<'a, T>
where
    T: SessionSetupProperties,
{
    last_setup_response: Option<SessionSetupResponse>,
    flags: Option<SessionFlags>,

    handler: Option<HandlerReference<ChannelMessageHandler>>,

    /// should always be set; this is Option to allow moving it out during setup,
    /// when it is being updated.
    preauth_hash: Option<PreauthHashState>,

    result: Option<Arc<Mutex<SessionAndChannel>>>,

    authenticator: Authenticator,
    upstream: &'a Upstream,
    conn_info: &'a Arc<ConnectionInfo>,

    // A place to store the current setup channel, until it is set into the info.
    channel: Option<ChannelInfo>,

    _phantom: std::marker::PhantomData<T>,
}

impl<'a, T> SessionSetup<'a, T>
where
    T: SessionSetupProperties,
{
    async fn new(
        user_name: &str,
        password: String,
        upstream: &'a Upstream,
        conn_info: &'a Arc<ConnectionInfo>,
        primary_session: Option<&Arc<Mutex<SessionAndChannel>>>,
    ) -> crate::Result<Self> {
        let username = Username::parse(user_name).map_err(|e| Error::SspiError(e.into()))?;
        let identity = AuthIdentity {
            username,
            password: Secret::new(password),
        };
        let authenticator = Authenticator::build(identity, conn_info)?;

        let mut result = Self {
            last_setup_response: None,
            flags: None,
            result: None,
            handler: None,
            preauth_hash: Some(conn_info.preauth_hash.clone()),
            authenticator,
            upstream: upstream,
            conn_info: conn_info,
            channel: None,
            _phantom: std::marker::PhantomData,
        };

        if primary_session.is_some() {
            result.set_session(primary_session.unwrap().clone()).await?;
        }

        Ok(result)
    }

    /// Common session setup logic.
    ///
    /// This function sets up a session against a connection, and it is somewhat abstrace.
    /// by calling impl functions, this function's behavior is modified to support both new sessions and binding to existing sessions.
    async fn setup(&mut self) -> crate::Result<Arc<Mutex<SessionAndChannel>>> {
        log::debug!(
            "Setting up session for user {} (@{}).",
            self.authenticator.user_name().account_name(),
            self.authenticator.user_name().domain_name().unwrap_or("")
        );

        let result = self._setup_loop().await;
        match result {
            Ok(()) => Ok(self.result.take().unwrap()),
            Err(e) => {
                log::error!("Failed to setup session: {}", e);
                T::error_cleanup(self)
                    .await
                    .or_else(|ce| {
                        log::error!("Failed to cleanup after setup error: {}", ce);
                        crate::Result::Ok(())
                    })
                    .or_else(|e| {
                        log::error!("Cleanup after setup error failed: {e}");
                        crate::Result::Ok(())
                    })?;
                return Err(e);
            }
        }
    }

    /// *DO NOT OVERLOAD*
    ///
    /// Performs the session setup negotiation.
    ///
    /// this function loops until the authentication is complete, requesting GSS tokens
    /// and passing them to the server.
    async fn _setup_loop(&mut self) -> crate::Result<()> {
        // While there's a response to process, do so.
        while !self.authenticator.is_authenticated()? {
            let next_buf = match self.last_setup_response.as_ref() {
                Some(response) => self.authenticator.next(&response.buffer).await?,
                None => self.authenticator.next(&[]).await?,
            };
            let is_auth_done = self.authenticator.is_authenticated()?;

            self.last_setup_response = match next_buf {
                AuthenticationStep::NextToken(next_buf) => {
                    // If keys are exchanged, set them up, to enable validation of next response!
                    let request = self.send_setup_request(next_buf).await?;
                    if is_auth_done {
                        self.preauth_hash = self.preauth_hash.take().unwrap().finish().into();
                        self.make_channel().await?;
                    }

                    let response = self.receive_setup_response(request.msg_id).await?;
                    let message_form = response.form;
                    let session_id = response.message.header.session_id;
                    let session_setup_response = response.message.content.to_sessionsetup()?;

                    // First iteration: construct a session state object.
                    // TODO: currently, there's a bug which prevents authentication on first attempt
                    // to complete successfully: since we need the session ID to construct the session state,
                    // which is required for channel construction and signature validation,
                    // the first request must arrive here, and then be validated.
                    if self.result.is_none() {
                        log::trace!("Creating session state with id {session_id}.");
                        self.set_session(T::init_session(self, session_id).await?.into())
                            .await?;
                    }

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
                        self.next_preauth_hash(&response.raw);
                    }

                    self.flags = Some(session_setup_response.session_flags);
                    Some(session_setup_response)
                }
                AuthenticationStep::Complete => None,
            };
        }

        self.flags.ok_or(Error::InvalidState(
            "Failed to complete authentication properly.".to_string(),
        ))?;

        log::trace!("setup success, finishing up.");
        T::on_setup_success(self).await?;

        Ok(())
    }

    async fn set_session(&mut self, session: Arc<Mutex<SessionAndChannel>>) -> crate::Result<()> {
        let session_id = session.lock().await?.session_id;
        self.handler = Some(ChannelMessageHandler::new(
            session_id,
            false, // prevent logoff once this ref is dropped.
            self.upstream,
            &session,
        ));

        self.upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))
            .unwrap()
            .session_started(&session)
            .await
            .unwrap();

        self.result = Some(session);

        Ok(())
    }

    async fn receive_setup_response(&mut self, for_msg_id: u64) -> crate::Result<IncomingMessage> {
        let is_auth_done = self.authenticator.is_authenticated()?;

        let expected_status = if is_auth_done {
            &[Status::Success]
        } else {
            &[Status::MoreProcessingRequired]
        };

        let roptions = ReceiveOptions::new()
            .with_status(expected_status)
            .with_msg_id_filter(for_msg_id);

        let channel_set_up = self.result.is_some()
            && self
                .result
                .as_ref()
                .unwrap()
                .lock()
                .await?
                .channel
                .is_some();
        let skip_security_validation = !is_auth_done && !channel_set_up;
        if self.handler.is_some() {
            log::trace!(
                "setup loop: receiving with channel handler; skip_security_validation={skip_security_validation}"
            );
            self.handler
                .as_ref()
                .unwrap()
                .recvo_internal(roptions, skip_security_validation)
                .await
        } else {
            assert!(skip_security_validation);
            log::trace!("setup loop: receiving with upstream handler");
            self.upstream.handler.recvo(roptions).await
        }
    }

    async fn send_setup_request(&mut self, buf: Vec<u8>) -> crate::Result<SendMessageResult> {
        // We'd like to update preauth hash with the last request before accept.
        // therefore we update it here for the PREVIOUS repsponse, assuming that we get an empty request when done.
        let request = T::make_request(self, buf).await?;

        let send_result = if self.handler.is_some() {
            log::trace!("setup loop: sending with channel handler");
            self.handler.as_ref().unwrap().sendo(request).await?
        } else {
            log::trace!("setup loop: sending with upstream handler");
            self.upstream.sendo(request).await?
        };

        self.next_preauth_hash(&send_result.raw.as_ref().unwrap());
        Ok(send_result)
    }

    /// Initializes the channel that is resulted from the current session setup.
    /// - Calls `T::on_session_key_exchanged` before setting up the channel.
    /// - Sets `self.channel` to the instantiated channel.
    /// - Calls `T::on_channel_set_up` after setting up the channel.
    async fn make_channel(&mut self) -> crate::Result<()> {
        T::on_session_key_exchanged(self).await?;
        log::trace!("Session keys are set.");

        let channel_info = ChannelInfo::new(
            &self.session_key()?,
            &self.preauth_hash_value(),
            &self.conn_info,
            T::is_session_primary(),
        )?;

        self.channel = Some(channel_info);

        T::on_channel_set_up(self).await?;

        log::trace!("Session inserted into worker.");
        Ok(())
    }

    fn session_key(&self) -> crate::Result<KeyToDerive> {
        self.authenticator.session_key()
    }

    fn preauth_hash_value(&self) -> Option<PreauthHashValue> {
        self.preauth_hash
            .as_ref()
            .unwrap()
            .unwrap_final_hash()
            .copied()
    }

    fn next_preauth_hash(&mut self, data: &IoVec) -> &PreauthHashState {
        self.preauth_hash = Some(self.preauth_hash.take().unwrap().next(data));
        self.preauth_hash.as_ref().unwrap()
    }

    /// Takes out the current channel, and sets it into the common session and channel info.
    async fn put_channel_to_state(&mut self) -> crate::Result<()> {
        log::trace!("Setting up channel into session state.");
        let mut session_lock = self.result.as_ref().unwrap().lock().await?;
        session_lock.set_channel(self.channel.take().unwrap());
        Ok(())
    }
}

#[maybe_async(AFIT)]
trait SessionSetupProperties {
    /// This function is called when setup error is encountered, to perform any necessary cleanup.
    async fn error_cleanup<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties;

    fn _make_default_request(buffer: Vec<u8>) -> OutgoingMessage {
        OutgoingMessage::new(
            SessionSetupRequest::new(
                buffer,
                SessionSecurityMode::new().with_signing_enabled(true),
                SetupRequestFlags::new(),
            )
            .into(),
        )
        .with_return_raw_data(true)
    }

    async fn make_request<T>(
        _setup: &mut SessionSetup<'_, T>,
        buffer: Vec<u8>,
    ) -> crate::Result<OutgoingMessage>
    where
        T: SessionSetupProperties,
    {
        Ok(Self::_make_default_request(buffer))
    }

    async fn init_session<T>(
        _setup: &'_ SessionSetup<'_, T>,
        _session_id: u64,
    ) -> crate::Result<Arc<Mutex<SessionAndChannel>>>
    where
        T: SessionSetupProperties;

    async fn on_session_key_exchanged<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        // Default implementation does nothing.
        Ok(())
    }

    async fn on_channel_set_up<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties;

    async fn on_setup_success<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties;

    fn is_session_primary() -> bool;
}

struct SmbSessionBind;
impl SessionSetupProperties for SmbSessionBind {
    async fn make_request<T>(
        setup: &mut SessionSetup<'_, T>,
        buffer: Vec<u8>,
    ) -> crate::Result<OutgoingMessage>
    where
        T: SessionSetupProperties,
    {
        let mut request = Self::_make_default_request(buffer);
        request
            .message
            .content
            .as_mut_sessionsetup()
            .unwrap()
            .flags
            .set_binding(true);
        Ok(request)
    }

    async fn error_cleanup<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        if setup.result.is_none() {
            log::warn!("No session to cleanup in binding.");
            return Ok(());
        }
        setup
            .upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(setup.result.as_ref().unwrap())
            .await
    }

    async fn init_session<T>(
        _setup: &SessionSetup<'_, T>,
        _session_id: u64,
    ) -> crate::Result<Arc<Mutex<SessionAndChannel>>>
    where
        T: SessionSetupProperties,
    {
        panic!("(Primary) Session should be provided in construction, rather than during setup!");
    }

    fn is_session_primary() -> bool {
        false
    }

    async fn on_channel_set_up<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        // when binding a session, setting the channel takes place only at the very end of the setup.
        // up until that point, we use the channel of the primary session to perform signing.
        Ok(())
    }

    async fn on_setup_success<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        _setup.put_channel_to_state().await
    }
}

struct SmbSessionNew;
impl SessionSetupProperties for SmbSessionNew {
    async fn error_cleanup<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        if setup.result.is_none() {
            log::trace!("No session to cleanup in setup.");
            return Ok(());
        }

        log::trace!("Invalidating session before cleanup.");
        let session = setup.result.as_ref().unwrap();
        {
            let session_lock = session.lock().await?;
            session_lock.session.lock().await?.invalidate();
        }

        setup
            .upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(setup.result.as_ref().unwrap())
            .await
    }

    async fn on_session_key_exchanged<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        // Only on new sessions we need to initialize the session state with the keys.
        log::trace!("Session keys exchanged. Setting up session state.");
        setup
            .result
            .as_ref()
            .unwrap()
            .lock()
            .await?
            .session
            .lock()
            .await?
            .setup(
                &setup.session_key()?,
                &setup.preauth_hash_value(),
                &setup.conn_info,
            )
    }

    async fn on_setup_success<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        log::trace!("Session setup successful");
        let result = setup.result.as_ref().unwrap().lock().await?;
        let mut session = result.session.lock().await?;
        session.ready(setup.flags.unwrap(), &setup.conn_info)
    }

    fn is_session_primary() -> bool {
        false
    }

    async fn on_channel_set_up<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        // When creating a new session, right after setup we need to sign the session setup response,
        // so we set the channel into the session state right away.
        _setup.put_channel_to_state().await
    }

    async fn init_session<T>(
        _setup: &SessionSetup<'_, T>,
        session_id: u64,
    ) -> crate::Result<Arc<Mutex<SessionAndChannel>>>
    where
        T: SessionSetupProperties,
    {
        let session_info = SessionInfo::new(session_id);
        let session_info = Arc::new(Mutex::new(session_info));

        let result = SessionAndChannel::new(session_id, session_info.clone());
        let session_info = Arc::new(Mutex::new(result));

        Ok(session_info)
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

pub struct ChannelMessageHandler {
    session_id: u64,
    upstream: Upstream,
    /// indicates whether dropping this handler should logoff the session.
    owns: bool,

    session_state: Arc<Mutex<SessionAndChannel>>,
    // channel_info: Arc<ChannelInfo>,
    dropping: AtomicBool,
}

impl ChannelMessageHandler {
    fn new(
        session_id: u64,
        is_primary: bool,
        upstream: &Upstream,
        setup_result: &Arc<Mutex<SessionAndChannel>>,
    ) -> HandlerReference<ChannelMessageHandler> {
        HandlerReference::new(ChannelMessageHandler {
            session_id,
            owns: is_primary,
            upstream: upstream.clone(),
            session_state: setup_result.clone(),
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
            let state = state.session.lock().await?;
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
            .session_ended(&self.session_state)
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
        let session = self.session_state.lock().await?;
        let session = session.session.lock().await?;
        // allow unsigned messages only if the session is anonymous or guest.
        // this is enforced against configuration when setting up the session.
        let unsigned_allowed = session.allow_unsigned()?;
        let encryption_required = session.is_ready() && session.should_encrypt()?;

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
    /// Same as [`ChannelMessageHandler::recvo`], but possible skips security validation.
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
            let session = session.session.lock().await?;
            assert!(session.is_initial());
        }

        Ok(incoming)
    }
}

impl MessageHandler for ChannelMessageHandler {
    #[maybe_async]
    async fn sendo(&self, mut msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        {
            let session = self.session_state.lock().await?;
            let session = session.session.lock().await?;
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
impl Drop for ChannelMessageHandler {
    fn drop(&mut self) {
        if !self.is_primary {
            return;
        }
        self.logoff().unwrap_or_else(|e| {
            log::error!("Failed to logoff: {e}",);
        });
    }
}

#[cfg(feature = "async")]
impl Drop for ChannelMessageHandler {
    fn drop(&mut self) {
        if !self.owns {
            return;
        }

        if self
            .dropping
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }

        let session_id = self.session_id;
        let is_primary = self.owns;
        let upstream = self.upstream.clone();
        let session_state = self.session_state.clone();
        tokio::task::spawn(async move {
            let temp_handler = ChannelMessageHandler {
                session_id,
                owns: is_primary,
                upstream,
                session_state,
                dropping: AtomicBool::new(false),
            };
            temp_handler.logoff_async().await;
        });
    }
}
