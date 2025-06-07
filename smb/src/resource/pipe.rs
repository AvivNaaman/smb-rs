use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

use super::ResourceHandle;
use crate::{
    msg_handler::ReceiveOptions,
    packets::{
        guid::Guid,
        rpc::{interface::*, pdu::*},
        smb2::{
            FsctlCodes, IoctlBuffer, IoctlReqData, IoctlRequest, IoctlRequestFlags, ReadRequest,
            WriteRequest,
        },
    },
};
use maybe_async::*;
pub struct Pipe {
    handle: ResourceHandle,
}

impl Pipe {
    pub fn new(handle: ResourceHandle) -> Self {
        Pipe { handle }
    }

    pub fn handle(&self) -> &ResourceHandle {
        &self.handle
    }

    #[maybe_async]
    pub async fn bind<I>(self) -> crate::Result<I>
    where
        I: RpcInterface<PipeRpcConnection>,
    {
        PipeRpcConnection::bind::<I>(self).await
    }
}

pub struct PipeRpcConnection {
    pipe: Pipe,
    next_call_id: u32,
    /// Selected, accepted, context ID from binding.
    context_id: u16,
}

impl PipeRpcConnection {
    #[maybe_async]
    pub async fn bind<I>(mut pipe: Pipe) -> crate::Result<I>
    where
        I: RpcInterface<PipeRpcConnection>,
    {
        let tranfer_syntaxes: [DceRpcSyntaxId; 2] = [
            DceRpcSyntaxId {
                uuid: Guid::from_str("71710533-beba-4937-8319-b5dbef9ccc36").unwrap(), // NDR64
                version: 1,
            },
            DceRpcSyntaxId {
                uuid: Guid::from_str("6cb71c2c-9812-4540-0300-000000000000").unwrap(),
                version: 2,
            },
        ];
        let context_elements = Self::make_bind_contexts(I::syntax_id(), &tranfer_syntaxes);

        const START_CALL_ID: u32 = 2;
        const DEFAULT_FRAG_LIMIT: u16 = 4280;
        const NO_ASSOC_GROUP_ID: u32 = 0;
        let bind_ack = Self::rpc_rw(
            &mut pipe,
            START_CALL_ID,
            DcRpcCoPktBind {
                max_xmit_frag: DEFAULT_FRAG_LIMIT,
                max_recv_frag: DEFAULT_FRAG_LIMIT,
                assoc_group_id: NO_ASSOC_GROUP_ID,
                context_elements,
            }
            .into(),
        )
        .await?;

        let bind_ack = match bind_ack.content() {
            DcRpcCoPktResponseContent::BindAck(bind_ack) => {
                log::debug!("Bounded to pipe with port spec {}", bind_ack.port_spec);
                bind_ack
            }
            _ => {
                return Err(crate::Error::InvalidMessage(format!(
                    "Expected BindAck, got: {:?}",
                    bind_ack
                )));
            }
        };

        let context_id = Self::check_bind_results(&bind_ack, &tranfer_syntaxes)?;

        Ok(I::new(PipeRpcConnection {
            pipe,
            next_call_id: START_CALL_ID + 1,
            context_id,
        }))
    }

    fn make_bind_contexts(
        syntax_id: DceRpcSyntaxId,
        transfer_syntaxes: &[DceRpcSyntaxId],
    ) -> Vec<DcRpcCoPktBindContextElement> {
        let mut result = vec![];

        for (i, syntax) in transfer_syntaxes.into_iter().enumerate() {
            result.push(DcRpcCoPktBindContextElement {
                context_id: i as u16,
                abstract_syntax: syntax_id.clone(),
                transfer_syntaxes: vec![syntax.clone()],
            });
        }

        result
    }

    fn check_bind_results(
        bind_ack: &DcRpcCoPktBindAck,
        transfer_syntaxes: &[DceRpcSyntaxId],
    ) -> crate::Result<u16> {
        const BIND_TIME_FEATURE_NEG_PREFIX: &str = "6cb71c2c-9812-4540-";
        if bind_ack.results.len() != transfer_syntaxes.len() {
            return Err(crate::Error::InvalidMessage(format!(
                "BindAck results length {} does not match transfer syntaxes length {}",
                bind_ack.results.len(),
                transfer_syntaxes.len()
            )));
        }
        let mut context_id_selected = None;
        for (indx, (ack_context, syntax)) in
            bind_ack.results.iter().zip(transfer_syntaxes).enumerate()
        {
            if syntax
                .uuid
                .to_string()
                .starts_with(BIND_TIME_FEATURE_NEG_PREFIX)
            {
                // Bind time feature negotiation element. Currently ignored.
                log::debug!(
                    "Bind time feature negotiation flags: {:?}",
                    ack_context.result as u16
                );
                continue;
            }
            if ack_context.result != DceRpcCoPktBindAckDefResult::Acceptance {
                return Err(crate::Error::InvalidMessage(format!(
                    "BindAck result for syntax {} was not acceptance: {:?}",
                    syntax, ack_context
                )));
            }
            if &ack_context.syntax != syntax {
                return Err(crate::Error::InvalidMessage(format!(
                    "BindAck abstract syntax {} does not match expected {}",
                    ack_context.syntax, syntax
                )));
            }
            context_id_selected = Some(indx as u16);
        }

        if let Some(context_id) = context_id_selected {
            log::debug!("Selected context ID: {}", context_id);
            Ok(context_id)
        } else {
            Err(crate::Error::InvalidMessage(
                "No accepted context ID found in BindAck".to_string(),
            ))
        }
    }

    pub const PACKED_DREP: u32 = 0x10;
    /// Performs a read+write operation on the pipe, sending a request and receiving it's response.
    #[maybe_async]
    async fn rpc_rw(
        pipe: &mut Pipe,
        call_id: u32,
        to_send: DcRpcCoPktRequestContent,
    ) -> crate::Result<DceRpcCoResponsePkt> {
        const READ_WRITE_PIPE_OFFSET: u64 = 0;
        let dcerpc_request_buffer: Vec<u8> = DceRpcCoRequestPkt::new(
            to_send,
            call_id,
            DceRpcCoPktFlags::new()
                .with_first_frag(true)
                .with_last_frag(true),
            Self::PACKED_DREP,
        )
        .try_into()?;
        let exp_write_size = dcerpc_request_buffer.len() as u32;
        let write_result = pipe
            .send_recvo(
                WriteRequest {
                    offset: READ_WRITE_PIPE_OFFSET,
                    file_id: pipe.handle.file_id,
                    flags: Default::default(),
                    buffer: dcerpc_request_buffer,
                }
                .into(),
                ReceiveOptions::new().with_allow_async(true),
            )
            .await?;
        if write_result.message.content.to_write()?.count != exp_write_size {
            return Err(crate::Error::InvalidMessage(
                "Failed to write the full request to the pipe".to_string(),
            ));
        }

        let read_result = pipe
            .send_recvo(
                ReadRequest {
                    flags: Default::default(),
                    length: 1024,
                    offset: READ_WRITE_PIPE_OFFSET,
                    file_id: pipe.handle.file_id,
                    minimum_count: DceRpcCoRequestPkt::COMMON_SIZE_BYTES as u32,
                }
                .into(),
                ReceiveOptions::new().with_allow_async(true),
            )
            .await?;
        let content = read_result.message.content.to_read()?;
        let response = DceRpcCoResponsePkt::try_from(content.buffer.as_ref())?;

        if response.packed_drep() != Self::PACKED_DREP {
            return Err(crate::Error::InvalidMessage(format!(
                "Currently Unsupported packed DREP: {}",
                response.packed_drep()
            )));
        }

        if !response.pfc_flags().first_frag() || !response.pfc_flags().last_frag() {
            return Err(crate::Error::InvalidMessage(
                "Expected first and last fragment flags to be set".to_string(),
            ));
        }

        Ok(response)
    }

    pub fn pipe(&self) -> &Pipe {
        &self.pipe
    }
}

impl BoundRpcConnection for PipeRpcConnection {
    #[maybe_async]
    async fn send_receive_raw(&mut self, opnum: u16, stub_input: &[u8]) -> crate::Result<Vec<u8>> {
        let req = DcRpcCoPktRequest {
            alloc_hint: DcRpcCoPktRequest::ALLOC_HINT_NONE,
            context_id: self.context_id,
            opnum,
            stub_data: stub_input.to_vec(),
        }
        .into();
        let req = DceRpcCoRequestPkt::new(
            req,
            self.next_call_id,
            DceRpcCoPktFlags::new()
                .with_first_frag(true)
                .with_last_frag(true),
            Self::PACKED_DREP, // Packed DREP
        );
        self.next_call_id += 1;

        let req_data: Vec<u8> = req.try_into()?;

        let res = self
            .pipe
            .handle
            .send_recvo(
                IoctlRequest {
                    ctl_code: FsctlCodes::PipeTransceive as u32,
                    file_id: self.pipe.file_id,
                    max_input_response: 1024,
                    max_output_response: 1024,
                    flags: IoctlRequestFlags::new().with_is_fsctl(true),
                    buffer: IoctlReqData::FsctlPipeTransceive(IoctlBuffer::from(req_data)),
                }
                .into(),
                ReceiveOptions::new().with_allow_async(true),
            )
            .await?;
        let res = res.message.content.to_ioctl()?;
        if res.ctl_code != FsctlCodes::PipeTransceive as u32 {
            return Err(crate::Error::InvalidMessage(format!(
                "Expected FSCTL_PIPE_TRANSCEIVE, got: {}",
                res.ctl_code
            )));
        }

        let rpc_reply = DceRpcCoResponsePkt::try_from(res.out_buffer.as_ref())?;

        if rpc_reply.packed_drep() != Self::PACKED_DREP {
            return Err(crate::Error::InvalidMessage(format!(
                "Currently Unsupported packed DREP: {}",
                rpc_reply.packed_drep()
            )));
        }

        if !rpc_reply.pfc_flags().first_frag() || !rpc_reply.pfc_flags().last_frag() {
            return Err(crate::Error::InvalidMessage(
                "Expected first and last fragment flags to be set".to_string(),
            ));
        }

        let response = match rpc_reply.into_content() {
            DcRpcCoPktResponseContent::Response(dc_rpc_co_pkt_response) => dc_rpc_co_pkt_response,
            content => {
                return Err(crate::Error::InvalidMessage(format!(
                    "Expected DceRpcCoPktResponseContent::Response, got: {:?}",
                    content
                )));
            }
        };

        if response.context_id != self.context_id {
            return Err(crate::Error::InvalidMessage(format!(
                "Response context ID {} does not match expected {}",
                response.context_id, self.context_id
            )));
        }

        Ok(response.stub_data)
    }
}

impl Deref for Pipe {
    type Target = ResourceHandle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl DerefMut for Pipe {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}
