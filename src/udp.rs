use bytes::Bytes;
use etherparse::PacketBuilder;
use futures::{ready, Sink, SinkExt, Stream};
use smoltcp::wire::UdpPacket;
use std::{
    fmt, mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::PollSender;
use tracing::trace;

use crate::packet::{AnyIpPktFrame, IpPacket};

pub struct UdpMessage {
    pub payload: Bytes,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}

impl UdpMessage {
    /// Flips the local and remote addresses, reversing message direction.
    pub fn flip(mut self) -> Self {
        mem::swap(&mut self.local_addr, &mut self.remote_addr);
        self
    }
}

#[derive(Debug)]
pub enum UdpError {
    AddressTypeMismatch,
    ChannelSendError,
    IoError(std::io::Error),
}

impl fmt::Display for UdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UdpError::AddressTypeMismatch => write!(f, "Address type mismatch"),
            UdpError::ChannelSendError => write!(f, "Channel send error"),
            UdpError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for UdpError {}

impl From<std::io::Error> for UdpError {
    fn from(e: std::io::Error) -> Self {
        UdpError::IoError(e)
    }
}

pub struct UdpSocket {
    udp_rx: Receiver<AnyIpPktFrame>,
    stack_tx: PollSender<AnyIpPktFrame>,
}

impl UdpSocket {
    pub(super) fn new(udp_rx: Receiver<AnyIpPktFrame>, stack_tx: Sender<AnyIpPktFrame>) -> Self {
        Self {
            udp_rx,
            stack_tx: PollSender::new(stack_tx),
        }
    }

    pub fn split(self) -> (ReadHalf, WriteHalf) {
        (
            ReadHalf {
                udp_rx: self.udp_rx,
            },
            WriteHalf {
                stack_tx: self.stack_tx,
            },
        )
    }
}

pub struct ReadHalf {
    udp_rx: Receiver<AnyIpPktFrame>,
}

pub struct WriteHalf {
    stack_tx: PollSender<AnyIpPktFrame>,
}

impl Stream for ReadHalf {
    type Item = UdpMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(self.udp_rx.poll_recv(cx)) {
                Some(frame) => {
                    if let Some(msg) = Self::process_frame_fast(frame) {
                        return Poll::Ready(Some(msg));
                    }
                    // Continue loop to try next frame
                }
                None => return Poll::Ready(None),
            }
        }
    }
}

impl ReadHalf {
    #[inline]
    fn process_frame_fast(frame: AnyIpPktFrame) -> Option<UdpMessage> {
        let slice = frame.as_slice();

        let ip_packet = IpPacket::new_checked(slice).ok()?;
        let udp_slice = ip_packet.payload();
        let udp_packet = UdpPacket::new_checked(udp_slice).ok()?;

        let src_addr = SocketAddr::new(ip_packet.src_addr(), udp_packet.src_port());
        let dst_addr = SocketAddr::new(ip_packet.dst_addr(), udp_packet.dst_port());

        let payload = Bytes::copy_from_slice(udp_packet.payload());

        trace!("UDP {} -> {}, {} bytes", src_addr, dst_addr, payload.len());

        Some(UdpMessage {
            payload,
            local_addr: src_addr,
            remote_addr: dst_addr,
        })
    }
}

impl Sink<UdpMessage> for WriteHalf {
    type Error = UdpError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.stack_tx
            .poll_ready_unpin(cx)
            .map_err(|_| UdpError::ChannelSendError)
    }

    fn start_send(mut self: Pin<&mut Self>, msg: UdpMessage) -> Result<(), Self::Error> {
        if msg.payload.is_empty() {
            return Ok(());
        }

        let packet_data = self.build_packet(&msg)?;

        self.stack_tx
            .start_send_unpin(packet_data)
            .map_err(|_| UdpError::ChannelSendError)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.stack_tx
            .poll_flush_unpin(cx)
            .map_err(|_| UdpError::ChannelSendError)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.stack_tx
            .poll_close_unpin(cx)
            .map_err(|_| UdpError::ChannelSendError)
    }
}

impl WriteHalf {
    #[inline]
    fn build_packet(&self, msg: &UdpMessage) -> Result<Vec<u8>, UdpError> {
        let builder = match (msg.local_addr, msg.remote_addr) {
            (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
                PacketBuilder::ipv4(local.ip().octets(), remote.ip().octets(), 20)
                    .udp(msg.local_addr.port(), msg.remote_addr.port())
            }
            (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
                PacketBuilder::ipv6(local.ip().octets(), remote.ip().octets(), 20)
                    .udp(msg.local_addr.port(), msg.remote_addr.port())
            }
            _ => return Err(UdpError::AddressTypeMismatch),
        };

        let packet_size = builder.size(msg.payload.len());
        let mut buffer = Vec::with_capacity(packet_size);

        builder
            .write(&mut buffer, &msg.payload)
            .map_err(|e| UdpError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        Ok(buffer)
    }
}
