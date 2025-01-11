use binrw::prelude::*;
use sspi::{AuthIdentity, Secret, Username};
use std::{cell::OnceCell, error::Error, io::Cursor};

use crate::{
    authenticator::GssAuthenticator,
    msg_handler::{
        HandlerReference, IncomingMessage, MessageHandler, OutgoingMessage, ReceiveOptions,
        SendMessageResult,
    },
    packets::{
        netbios::NetBiosTcpMessage,
        smb2::{
            header::{Header, Status},
            message::{Content, Message},
            negotiate::SigningAlgorithmId,
            session_setup::SessionSetupRequest,
        },
    },
    smb_client::ClientMessageHandler,
    smb_crypto::{Crypto, SigningAlgo},
    smb_tree::Tree,
};

type SigningKeyValue = [u8; 16];
type UpstreamHandlerRef = HandlerReference<ClientMessageHandler>;

pub struct Session {
    is_set_up: bool,
    handler: HandlerReference<SessionMessageHandler>,
}

impl Session {
    pub fn new(upstream: UpstreamHandlerRef) -> Session {
        Session {
            is_set_up: false,
            handler: SessionMessageHandler::new(upstream),
        }
    }

    pub fn setup(&mut self, user_name: String, password: String) -> Result<(), Box<dyn Error>> {
        log::debug!("Setting up session for user {}.", user_name);
        // Build the authenticator.
        let (mut authenticator, next_buf) = {
            let handler = self.handler.borrow();
            let handler = handler.upstream.borrow();
            let negotate_state = handler.negotiate_state().unwrap();
            let identity = AuthIdentity {
                username: Username::new(&user_name, Some("WORKGROUP"))?,
                password: Secret::new(password),
            };
            GssAuthenticator::build(negotate_state.get_gss_token(), identity)?
        };

        let request = OutgoingMessage::new(Message::new(Content::SessionSetupRequest(
            SessionSetupRequest::new(next_buf),
        )));

        // response hash is processed later, in the loop.
        let response = self.handler.sendo_recvo(
            request,
            ReceiveOptions::new().status(Status::MoreProcessingRequired),
        )?;

        // Set session id.
        self.handler
            .borrow_mut()
            .session_id
            .set(response.message.header.session_id)
            .map_err(|_| "Session ID already set!")?;

        let mut response = Some(response);
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

            let next_buf = match last_setup_response.as_ref() {
                Some(response) => authenticator.next(&response.buffer)?,
                None => authenticator.next(&vec![])?,
            };

            response = match next_buf {
                Some(next_buf) => {
                    // We'd like to update preauth hash with the last request before accept.
                    // therefore we update it here for the PREVIOUS repsponse, assuming that we get an empty request when done.
                    let mut request = OutgoingMessage::new(Message::new(
                        Content::SessionSetupRequest(SessionSetupRequest::new(next_buf)),
                    ));
                    let is_about_to_finish = authenticator.keys_exchanged() && !self.is_set_up;
                    request.finalize_preauth_hash = is_about_to_finish;
                    let result = self.handler.sendo(request)?;

                    // Keys exchanged? We can set-up the session!
                    if is_about_to_finish {
                        // Derive keys and set-up the final session.
                        let ntlm_key = authenticator.session_key()?.to_vec();
                        // Derive signing key, and set-up the session.
                        self.key_setup(&ntlm_key, result.preauth_hash.unwrap())?;
                    }

                    let expected_status = if is_about_to_finish {
                        Status::Success
                    } else {
                        Status::MoreProcessingRequired
                    };
                    let response = self
                        .handler
                        .recvo(ReceiveOptions::new().status(expected_status))?;

                    Some(response)
                }
                None => None,
            };
        }
        log::info!("Session setup complete.");
        Ok(())
    }

    pub fn key_setup(
        &mut self,
        exchanged_session_key: &Vec<u8>,
        preauth_integrity_hash: [u8; 64],
    ) -> Result<(), Box<dyn Error>> {
        self.handler.borrow_mut().signing_key = Some(Self::derive_signing_key(
            exchanged_session_key,
            preauth_integrity_hash,
        )?);
        self.is_set_up = true;
        log::debug!("Session signing key set.");
        Ok(())
    }

    fn derive_signing_key(
        exchanged_session_key: &Vec<u8>,
        preauth_integrity_hash: [u8; 64],
    ) -> Result<[u8; 16], Box<dyn Error>> {
        assert!(exchanged_session_key.len() == 16);

        let mut session_key = [0; 16];
        session_key.copy_from_slice(&exchanged_session_key[0..16]);
        Ok(
            Crypto::kbkdf_hmacsha256(&session_key, b"SMBSigningKey\x00", &preauth_integrity_hash)?
                .try_into()
                .unwrap(),
        )
    }

    pub fn signing_enabled(&self) -> bool {
        true
    }

    pub fn tree_connect(&mut self, name: String) -> Result<Tree, Box<dyn Error>> {
        let mut tree = Tree::new(name, self.handler.clone());
        tree.connect()?;
        Ok(tree)
    }

    fn logoff(&mut self) -> Result<(), Box<dyn Error>> {
        log::debug!("Logging off session.");

        let _response = self
            .handler
            .send_recv(Content::LogoffRequest(Default::default()))?;

        // Reset session ID and keys.
        self.handler.borrow_mut().session_id.take();
        self.handler.borrow_mut().signing_key.take();
        self.is_set_up = false;

        log::info!("Session logged off.");

        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.logoff().unwrap_or_else(|e| {
            log::error!("Failed to logoff: {}", e);
        });
    }
}

#[derive(Debug)]
pub struct MessageSigner {
    signing_algo: Box<dyn SigningAlgo>,
}

impl MessageSigner {
    pub fn new(signing_algo: Box<dyn SigningAlgo>) -> MessageSigner {
        MessageSigner { signing_algo }
    }

    pub fn verify_signature(
        &mut self,
        header: &mut Header,
        raw_data: &NetBiosTcpMessage,
    ) -> Result<(), Box<dyn Error>> {
        let calculated_signature = self.calculate_signature(header, raw_data)?;
        if calculated_signature != header.signature {
            return Err("Signature verification failed".into());
        }
        log::debug!(
            "Signature verification passed (signature={}).",
            header.signature
        );
        Ok(())
    }

    pub fn sign_message(
        &mut self,
        header: &mut Header,
        raw_data: &mut NetBiosTcpMessage,
    ) -> Result<(), Box<dyn Error>> {
        header.signature = self.calculate_signature(header, raw_data)?;
        // Update raw data to include the signature.
        let mut header_writer = Cursor::new(&mut raw_data.content[0..Header::STRUCT_SIZE]);
        header.write(&mut header_writer)?;
        log::debug!(
            "Message #{} signed (signature={}).",
            header.message_id,
            header.signature
        );
        Ok(())
    }

    fn calculate_signature(
        &mut self,
        header: &mut Header,
        raw_message: &NetBiosTcpMessage,
    ) -> Result<u128, Box<dyn Error>> {
        // Write header.
        let signture_backup = header.signature;
        header.signature = 0;
        let mut header_bytes = Cursor::new([0; Header::STRUCT_SIZE]);
        header.write(&mut header_bytes)?;
        header.signature = signture_backup;
        self.signing_algo.start(&header);
        self.signing_algo.update(&header_bytes.into_inner());

        // And write rest of the raw message.
        let message_body = &raw_message.content[Header::STRUCT_SIZE..];
        self.signing_algo.update(message_body);

        Ok(self.signing_algo.finalize())
    }
}

pub struct SessionMessageHandler {
    session_id: OnceCell<u64>,
    signing_key: Option<SigningKeyValue>,
    signing_algo: SigningAlgorithmId,
    upstream: UpstreamHandlerRef,
}

impl SessionMessageHandler {
    pub fn new(upstream: UpstreamHandlerRef) -> HandlerReference<SessionMessageHandler> {
        let signing_algo = upstream
            .handler
            .borrow()
            .negotiate_state()
            .unwrap()
            .get_signing_algo();
        HandlerReference::new(SessionMessageHandler {
            session_id: OnceCell::new(),
            signing_key: None,
            signing_algo,
            upstream,
        })
    }

    pub fn should_sign(&self) -> bool {
        self.signing_key.is_some()
    }

    fn make_signer(&self) -> Result<MessageSigner, Box<dyn Error>> {
        if !self.should_sign() {
            return Err("Signing key is not set -- you must succeed a setup() to continue.".into());
        }

        debug_assert!(self.signing_key.is_some());

        Ok(MessageSigner::new(
            Crypto::make_signing_algo(self.signing_algo, self.signing_key.as_ref().unwrap())
                .unwrap(),
        ))
    }
}

impl MessageHandler for SessionMessageHandler {
    fn hsendo(
        &mut self,
        mut msg: OutgoingMessage,
    ) -> Result<SendMessageResult, Box<(dyn std::error::Error + 'static)>> {
        // Set signing configuration. Upstream handler shall take care of the rest.
        if self.should_sign() {
            msg.message.header.flags.set_signed(true);
            msg.signer = Some(self.make_signer()?);
        }
        msg.message.header.session_id = *self.session_id.get().or(Some(&0)).unwrap();
        self.upstream.borrow_mut().hsendo(msg)
    }

    fn hrecvo(
        &mut self,
        options: crate::msg_handler::ReceiveOptions,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        let mut incoming = self.upstream.borrow_mut().hrecvo(options)?;
        // TODO: check whether this is the correct case to do such a thing.
        if self.should_sign() {
            // Skip authentication is message ID is -1 or status is pending.
            if incoming.message.header.message_id != u64::MAX
                && incoming.message.header.status != Status::Pending
            {
                self.make_signer()?
                    .verify_signature(&mut incoming.message.header, &incoming.raw)?;
            }
        };
        Ok(incoming)
    }
}
