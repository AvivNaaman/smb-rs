use super::*;

/// Message handler a specific chanel.
///
/// This only makes sense, since session are not actuall able to send data
/// as "theirselves", but rather, through a channel.
pub struct ChannelMessageHandler {
    session_id: u64,
    channel_id: u32,
    upstream: Upstream,
    /// indicates whether dropping this handler should logoff the session.
    owns: bool,

    session_state: Arc<Mutex<SessionAndChannel>>,
    // channel_info: Arc<ChannelInfo>,
    dropping: AtomicBool,
}

impl ChannelMessageHandler {
    pub(crate) fn new(
        session_id: u64,
        channel_id: u32,
        is_primary: bool,
        upstream: &Upstream,
        setup_result: &Arc<Mutex<SessionAndChannel>>,
    ) -> HandlerReference<ChannelMessageHandler> {
        HandlerReference::new(ChannelMessageHandler {
            session_id,
            channel_id,
            owns: is_primary,
            upstream: upstream.clone(),
            session_state: setup_result.clone(),
            dropping: AtomicBool::new(false),
        })
    }

    #[maybe_async]
    pub async fn logoff(&self) -> crate::Result<()> {
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
    pub(crate) async fn recvo_internal(
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

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    pub fn session_state(&self) -> &Arc<Mutex<SessionAndChannel>> {
        &self.session_state
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
        if !self.owns {
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

        // TODO: This should be put back in Session....
        tokio::task::spawn(async move {
            let temp_handler = ChannelMessageHandler {
                session_id,
                channel_id: 0, // not used
                owns: is_primary,
                upstream,
                session_state,
                dropping: AtomicBool::new(false),
            };
            temp_handler.logoff_async().await;
        });
    }
}
