use super::*;

/// Session setup processor
pub(crate) struct SessionSetup<'a, T>
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
    upstream: &'a super::Upstream,
    conn_info: &'a Arc<ConnectionInfo>,

    // A place to store the current setup channel, until it is set into the info.
    channel: Option<ChannelInfo>,

    _phantom: std::marker::PhantomData<T>,
}

impl<'a, T> SessionSetup<'a, T>
where
    T: SessionSetupProperties,
{
    pub async fn new(
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
            upstream,
            conn_info,
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
    pub async fn setup(&mut self) -> crate::Result<Arc<Mutex<SessionAndChannel>>> {
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
                Err(e)
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
                        self.set_session(T::init_session(self, session_id).await?)
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

        self.next_preauth_hash(send_result.raw.as_ref().unwrap());
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
            self.conn_info,
            T::is_session_primary(),
        )?;

        self.channel = Some(channel_info);

        let mut session_lock = self.result.as_ref().unwrap().lock().await?;
        session_lock.set_channel(self.channel.take().unwrap());

        log::trace!("Channel for current setup has been initialized");
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

    pub fn upstream(&self) -> &'a super::Upstream {
        self.upstream
    }

    pub fn conn_info(&self) -> &'a Arc<ConnectionInfo> {
        self.conn_info
    }
}

#[maybe_async(AFIT)]
pub(crate) trait SessionSetupProperties {
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

    async fn on_setup_success<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties;

    fn is_session_primary() -> bool;
}

pub(crate) struct SmbSessionBind;
impl SessionSetupProperties for SmbSessionBind {
    async fn make_request<T>(
        _setup: &mut SessionSetup<'_, T>,
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

    async fn on_setup_success<T>(_setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        Ok(())
    }
}

pub(crate) struct SmbSessionNew;
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
                setup.conn_info,
            )
    }

    async fn on_setup_success<T>(setup: &mut SessionSetup<'_, T>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
    {
        log::trace!("Session setup successful");
        let result = setup.result.as_ref().unwrap().lock().await?;
        let mut session = result.session.lock().await?;
        session.ready(setup.flags.unwrap(), setup.conn_info)
    }

    fn is_session_primary() -> bool {
        false
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
