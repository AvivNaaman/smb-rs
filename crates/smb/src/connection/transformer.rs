use crate::sync_helpers::*;
use crate::{compression::*, msg_handler::*, session::SessionInfo};
use binrw::prelude::*;
use maybe_async::*;
use smb_msg::*;
use smb_transport::IoVec;
use std::{collections::HashMap, io::Cursor, sync::Arc};

use super::connection_info::ConnectionInfo;

/// The [`Transformer`] structure is responsible for transforming messages to and from bytes,
/// send over NetBios TCP connection.
/// See [`Transformer::transform_outgoing`] and [`Transformer::transform_incoming`] for transformation functions.
#[derive(Debug)]
pub struct Transformer {
    /// Sessions opened from this connection.
    sessions: Mutex<HashMap<u64, Arc<Mutex<SessionInfo>>>>,

    config: RwLock<TransformerConfig>
}

#[derive(Default, Debug)]
struct TransformerConfig {
    /// Compressors for this connection.
    compress: Option<(Compressor, Decompressor)>,

    negotiated: bool,
}

impl Transformer {
    /// Notifies that the connection negotiation has been completed,
    /// with the given [`ConnectionInfo`].
    #[maybe_async]
    pub async fn negotiated(&self, neg_info: &ConnectionInfo) -> crate::Result<()> {
        {
            let config = self.config.read().await?;
            if config.negotiated {
                return Err(crate::Error::InvalidState(
                    "Connection is already negotiated!".into(),
                ));
            }
        }

        let mut config = self.config.write().await?;
        if neg_info.dialect.supports_compression() && neg_info.config.compression_enabled {
            let compress = neg_info
                .negotiation
                .compression
                .as_ref()
                .map(|c| (Compressor::new(c), Decompressor::new(c)));
            config.compress = compress;
        }

        config.negotiated = true;

        Ok(())
    }

    /// Notifies that a session has started.
    #[maybe_async]
    pub async fn session_started(&self, session: Arc<Mutex<SessionInfo>>) -> crate::Result<()> {
        let rconfig = self.config.read().await?;
        if !rconfig.negotiated {
            return Err(crate::Error::InvalidState(
                "Connection is not negotiated yet!".to_string(),
            ));
        }

        let session_id = session.lock().await?.id();
        self.sessions
            .lock()
            .await?
            .insert(session_id, session.clone());

        Ok(())
    }

    /// Notifies that a session has ended.
    #[maybe_async]
    pub async fn session_ended(&self, session_id: u64) -> crate::Result<()> {
        let s = { self.sessions.lock().await?.remove(&session_id) };
        match s {
            Some(session_state) => {
                session_state.lock().await?.invalidate();
                Ok(())
            }
            None => Err(crate::Error::InvalidState("Session not found!".to_string())),
        }
    }

    /// (Internal)
    ///
    ///  Returns the session with the given ID.
    #[maybe_async]
    #[inline]
    async fn get_session(&self, session_id: u64) -> crate::Result<Arc<Mutex<SessionInfo>>> {
        self.sessions
            .lock()
            .await?
            .get(&session_id)
            .cloned()
            .ok_or(crate::Error::InvalidState(format!(
                "Session {session_id} not found!",
            )))
    }

    /// Transforms an outgoing message to a raw SMB message.
    #[maybe_async]
    pub async fn transform_outgoing(&self, mut msg: OutgoingMessage) -> crate::Result<IoVec> {
        let should_encrypt = msg.encrypt;
        let should_sign = msg.message.header.flags.signed();
        let set_session_id = msg.message.header.session_id;

        let mut outgoing_data = IoVec::default();
        // Plain header + content
        {
            let buffer = outgoing_data.add_owned(Vec::with_capacity(Header::STRUCT_SIZE));
            msg.message.write(&mut Cursor::new(buffer))?;
        }
        // Additional data, if any
        if msg.additional_data.as_ref().is_some_and(|d| !d.is_empty()) {
            outgoing_data.add_shared(msg.additional_data.unwrap().clone());
        }

        // 1. Sign
        if should_sign {
            debug_assert!(
                !should_encrypt,
                "Should not sign and encrypt at the same time!"
            );

            let mut signer = {
                self.get_session(set_session_id)
                    .await?
                    .lock()
                    .await?
                    .signer()?
                    .clone()
            };

            signer.sign_message(&mut msg.message.header, &mut outgoing_data)?;

            log::debug!(
                "Message #{} signed (signature={}).",
                msg.message.header.message_id,
                msg.message.header.signature
            );
        };

        // 2. Compress
        const COMPRESSION_THRESHOLD: usize = 1024;
        outgoing_data = {
            if msg.compress && outgoing_data.total_size() > COMPRESSION_THRESHOLD {
                let rconfig = self.config.read().await?;
                if let Some(compress) = &rconfig.compress {
                    // Build a vector of the entire data. In the future, this may be optimized to avoid copying.
                    // currently, there's not chained compression, and copy will occur anyway.
                    outgoing_data.consolidate();
                    let compressed = compress.0.compress(outgoing_data.first().unwrap())?;

                    let mut compressed_result = IoVec::default();
                    let write_compressed =
                        compressed_result.add_owned(Vec::with_capacity(compressed.total_size()));
                    compressed.write(&mut Cursor::new(write_compressed))?;
                    compressed_result
                } else {
                    outgoing_data
                }
            } else {
                outgoing_data
            }
        };

        // 3. Encrypt
        if should_encrypt {
            let session = self.get_session(set_session_id).await?;
            let encryptor = { session.lock().await?.encryptor()?.cloned() };
            if let Some(mut encryptor) = encryptor {
                debug_assert!(should_encrypt && !should_sign);

                let encrypted_header =
                    encryptor.encrypt_message(&mut outgoing_data, set_session_id)?;

                let write_encryption_header = outgoing_data
                    .insert_owned(0, Vec::with_capacity(EncryptedHeader::STRUCTURE_SIZE));

                encrypted_header.write(&mut Cursor::new(write_encryption_header))?;
            } else {
                return Err(crate::Error::TranformFailed(TransformError {
                    outgoing: true,
                    phase: TransformPhase::EncryptDecrypt,
                    session_id: Some(set_session_id),
                    why: "Message is required to be encrypted, but no encryptor is set up!",
                    msg_id: Some(msg.message.header.message_id),
                }));
            }
        }

        Ok(outgoing_data)
    }

    /// Transforms an incoming message buffer to an [`IncomingMessage`].
    #[maybe_async]
    pub async fn transform_incoming(&self, data: Vec<u8>) -> crate::Result<IncomingMessage> {
        let message = Response::try_from(data.as_ref())?;

        let mut form = MessageForm::default();

        // 3. Decrpt
        let (message, raw) = if let Response::Encrypted(encrypted_message) = message {
            let session = self
                .get_session(encrypted_message.header.session_id)
                .await?;
            let decryptor = { session.lock().await?.decryptor()?.cloned() };
            form.encrypted = true;
            match decryptor {
                Some(mut decryptor) => decryptor.decrypt_message(encrypted_message)?,
                None => {
                    return Err(crate::Error::TranformFailed(TransformError {
                        outgoing: false,
                        phase: TransformPhase::EncryptDecrypt,
                        session_id: Some(encrypted_message.header.session_id),
                        why: "Message is encrypted, but no decryptor is set up!",
                        msg_id: None,
                    }));
                }
            }
        } else {
            (message, data.to_vec())
        };

        // 2. Decompress
        debug_assert!(!matches!(message, Response::Encrypted(_)));
        let (message, raw) = if let Response::Compressed(compressed_message) = message {
            let rconfig = self.config.read().await?;
            form.compressed = true;
            match &rconfig.compress {
                Some(compress) => compress.1.decompress(&compressed_message)?,
                None => {
                    return Err(crate::Error::TranformFailed(TransformError {
                        outgoing: false,
                        phase: TransformPhase::CompressDecompress,
                        session_id: None,
                        why: "Compression is requested, but no decompressor is set up!",
                        msg_id: None,
                    }));
                }
            }
        } else {
            (message, raw)
        };

        let mut message = match message {
            Response::Plain(message) => message,
            _ => panic!("Unexpected message type"),
        };

        let iovec = IoVec::from(raw);
        // If fails, return TranformFailed, with message id.
        // this allows to notify the error to the task that was waiting for this message.
        match self
            .verify_plain_incoming(&mut message, &iovec, &mut form)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                log::error!("Failed to verify incoming message: {e:?}",);
                return Err(crate::Error::TranformFailed(TransformError {
                    outgoing: false,
                    phase: TransformPhase::SignVerify,
                    session_id: Some(message.header.session_id),
                    why: "Failed to verify incoming message!",
                    msg_id: Some(message.header.message_id),
                }));
            }
        };

        Ok(IncomingMessage {
            message,
            raw: iovec,
            form,
        })
    }

    /// (Internal)
    ///
    /// A helper method to verify the incoming message.
    /// This method is used to verify the signature of the incoming message,
    /// if such verification is required.
    #[maybe_async]
    async fn verify_plain_incoming(
        &self,
        message: &mut PlainResponse,
        raw: &IoVec,
        form: &mut MessageForm,
    ) -> crate::Result<()> {
        // Check if signing check is required.
        if form.encrypted
            || message.header.message_id == u64::MAX
            || message.header.status == Status::Pending as u32
            || !message.header.flags.signed()
        {
            return Ok(());
        }

        // Verify signature (if required, according to the spec)
        let session_id = message.header.session_id;
        let session = self.get_session(session_id).await?;
        let mut verifier = { session.lock().await?.signer()?.clone() };
        verifier.verify_signature(&mut message.header, raw)?;
        log::debug!(
            "Message #{} verified (signature={}).",
            message.header.message_id,
            message.header.signature
        );
        form.signed = true;
        Ok(())
    }
}

impl Default for Transformer {
    fn default() -> Self {
        Self {
            sessions: Default::default(),
            config: Default::default(),
        }
    }
}

/// An error that can occur during the transformation of messages.
#[derive(Debug)]
pub struct TransformError {
    /// If true, the error occurred while transforming an outgoing message.
    /// If false, it occurred while transforming an incoming message.
    pub outgoing: bool,
    pub phase: TransformPhase,
    pub session_id: Option<u64>,
    pub why: &'static str,
    /// If a message ID is available, it will be set here,
    /// for error-handling purposes.
    pub msg_id: Option<u64>,
}

impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.outgoing {
            write!(
                f,
                "Failed to transform outgoing message: {:?} (session_id: {:?}) - {}",
                self.phase, self.session_id, self.why
            )
        } else {
            write!(
                f,
                "Failed to transform incoming message: {:?} (session_id: {:?}) - {}",
                self.phase, self.session_id, self.why
            )
        }
    }
}

/// The phase of the transformation process.
#[derive(Debug)]
pub enum TransformPhase {
    /// Initial to/from bytes.
    EncodeDecode,
    /// Signature calculation and verification.
    SignVerify,
    /// Compression and decompression.
    CompressDecompress,
    /// Encryption and decryption.
    EncryptDecrypt,
}
