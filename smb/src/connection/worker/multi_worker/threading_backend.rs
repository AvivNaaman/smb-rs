use crate::connection::netbios_client::NetBiosClient;
use crate::sync_helpers::*;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use crate::{msg_handler::IncomingMessage, packets::netbios::NetBiosTcpMessage, Error};

use super::{backend_trait::MultiWorkerBackend, base::MultiWorkerBase};

#[derive(Debug)]
pub struct ThreadingBackend {
    worker: Arc<MultiWorkerBase<Self>>,

    /// The loops' handles for the worker.
    loop_handles: Mutex<Option<(JoinHandle<()>, JoinHandle<()>)>>,
    stopped: AtomicBool,
}

impl ThreadingBackend {
    fn is_cancelled(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl ThreadingBackend {
    fn loop_receive(&self, mut netbios_client: NetBiosClient) {
        debug_assert!(netbios_client.read_timeout().unwrap().is_some());
        while !self.is_cancelled() {
            let next = netbios_client.recieve_bytes();
            // Handle polling fail
            if let Err(Error::IoError(ref e)) = next {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    continue;
                }
            }
            match self.worker.loop_handle_incoming(next) {
                Ok(_) => {}
                Err(Error::NotConnected) => {
                    if self.is_cancelled() {
                        log::info!("Connection closed.");
                    } else {
                        log::error!("Connection closed.");
                    }
                    break;
                }
                Err(e) => {
                    log::error!("Error in worker recv loop: {}", e);
                }
            }
        }
    }

    fn loop_send(
        &self,
        mut netbios_client: NetBiosClient,
        send_channel: mpsc::Receiver<Option<NetBiosTcpMessage>>,
    ) {
        loop {
            match self.loop_send_next(send_channel.recv(), &mut netbios_client) {
                Ok(_) => {}
                Err(Error::NotConnected) => {
                    if self.is_cancelled() {
                        log::info!("Connection closed.");
                    } else {
                        log::error!("Connection closed!");
                    }
                    break;
                }
                Err(e) => {
                    log::error!("Error in worker send loop: {}", e);
                }
            }
        }
    }

    #[inline]
    fn loop_send_next(
        &self,
        message: Result<Option<NetBiosTcpMessage>, mpsc::RecvError>,
        netbios_client: &mut NetBiosClient,
    ) -> crate::Result<()> {
        self.worker.loop_handle_outgoing(message?, netbios_client)
    }
}

#[cfg(feature = "sync")]
impl MultiWorkerBackend for ThreadingBackend {
    type SendMessage = Option<NetBiosTcpMessage>;

    type AwaitingNotifier = std::sync::mpsc::Sender<crate::Result<IncomingMessage>>;
    type AwaitingWaiter = std::sync::mpsc::Receiver<crate::Result<IncomingMessage>>;

    fn start(
        netbios_client: NetBiosClient,
        worker: Arc<MultiWorkerBase<Self>>,
        send_channel_recv: mpsc::Receiver<Self::SendMessage>,
    ) -> crate::Result<Arc<Self>>
    where
        Self: std::fmt::Debug,
        Self::AwaitingNotifier: std::fmt::Debug,
    {
        let backend = Arc::new(Self {
            worker,
            loop_handles: Mutex::new(None),
            stopped: AtomicBool::new(false),
        });

        // Start the worker loops - send and receive.
        let netbios_receive = netbios_client;
        let backend_receive = backend.clone();
        let netbios_send = netbios_receive.try_clone()?;
        let backend_send = backend.clone();

        netbios_receive.set_read_timeout(Some(Duration::from_millis(100)))?;

        let handle1 = std::thread::spawn(move || backend_receive.loop_receive(netbios_receive));
        let handle2 =
            std::thread::spawn(move || backend_send.loop_send(netbios_send, send_channel_recv));

        backend
            .loop_handles
            .lock()
            .unwrap()
            .replace((handle1, handle2));

        Ok(backend)
    }

    fn stop(&self) -> crate::Result<()> {
        log::debug!("Stopping worker.");

        let handles = self
            .loop_handles
            .lock()
            .unwrap()
            .take()
            .ok_or(Error::NotConnected)?;

        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // wake up the sender to stop the loop.
        self.worker.sender.send(None).unwrap();

        // Join the threads.
        handles
            .0
            .join()
            .map_err(|_| Error::JoinError("Error stopping reciever".to_string()))?;

        handles
            .1
            .join()
            .map_err(|_| Error::JoinError("Error stopping sender".to_string()))?;

        Ok(())
    }

    fn wrap_msg_to_send(msg: NetBiosTcpMessage) -> Self::SendMessage {
        Some(msg)
    }

    fn make_notifier_awaiter_pair() -> (Self::AwaitingNotifier, Self::AwaitingWaiter) {
        std::sync::mpsc::channel()
    }

    fn wait_on_waiter(waiter: Self::AwaitingWaiter) -> crate::Result<IncomingMessage> {
        waiter
            .recv()
            .map_err(|_| Error::MessageProcessingError("Failed to receive message.".to_string()))?
    }

    fn send_notify(
        tx: Self::AwaitingNotifier,
        msg: crate::Result<IncomingMessage>,
    ) -> crate::Result<()> {
        tx.send(msg).map_err(|_| {
            Error::MessageProcessingError("Failed to send message to awaiting task.".to_string())
        })
    }

    fn make_send_channel_pair() -> (
        mpsc::Sender<Self::SendMessage>,
        mpsc::Receiver<Self::SendMessage>,
    ) {
        mpsc::channel()
    }
}
