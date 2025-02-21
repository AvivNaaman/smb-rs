use crate::connection::netbios_client::NetBiosClient;
use crate::sync_helpers::*;
use maybe_async::*;
use std::sync::Arc;

use crate::{msg_handler::IncomingMessage, packets::netbios::NetBiosTcpMessage};

use super::base::MultiWorkerBase;

#[maybe_async(AFIT)]
#[allow(async_fn_in_trait)] // for maybe_async.
pub trait MultiWorkerBackend {
    type SendMessage;
    type AwaitingNotifier;
    type AwaitingWaiter;

    async fn start(
        netbios_client: NetBiosClient,
        worker: Arc<MultiWorkerBase<Self>>,
        send_channel_recv: mpsc::Receiver<Self::SendMessage>,
    ) -> crate::Result<Arc<Self>>
    where
        Self: std::fmt::Debug + Sized,
        Self::AwaitingNotifier: std::fmt::Debug;
    async fn stop(&self) -> crate::Result<()>;

    fn wrap_msg_to_send(msg: NetBiosTcpMessage) -> Self::SendMessage;
    fn make_notifier_awaiter_pair() -> (Self::AwaitingNotifier, Self::AwaitingWaiter);
    // TODO: Consider typing the tx/rx in the trait, like the notifier/awaiter.
    fn make_send_channel_pair() -> (
        mpsc::Sender<Self::SendMessage>,
        mpsc::Receiver<Self::SendMessage>,
    );

    async fn wait_on_waiter(waiter: Self::AwaitingWaiter) -> crate::Result<IncomingMessage>;
    fn send_notify(
        tx: Self::AwaitingNotifier,
        msg: crate::Result<IncomingMessage>,
    ) -> crate::Result<()>;
}
