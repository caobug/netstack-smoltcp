use std::{
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, Stream};
use futures::{SinkExt, StreamExt};
use smoltcp::wire::IpProtocol;
use std::io::{Error, ErrorKind};
use std::time::Duration;
use tokio::sync::mpsc::{channel, Receiver};
use tokio_util::sync::PollSender;
use tracing::{debug, trace};

use crate::{
    filter::{IpFilter, IpFilters},
    packet::{AnyIpPktFrame, IpPacket},
    runner::Runner,
    tcp::TcpListener,
    udp::UdpSocket,
};

pub struct StackBuilder {
    enable_udp: bool,
    enable_tcp: bool,
    enable_icmp: bool,
    stack_buffer_size: usize,
    udp_buffer_size: usize,
    tcp_buffer_size: usize,
    ip_filters: IpFilters<'static>,
}

impl Default for StackBuilder {
    fn default() -> Self {
        Self {
            enable_udp: false,
            enable_tcp: false,
            enable_icmp: false,
            stack_buffer_size: 1024,
            udp_buffer_size: 512,
            tcp_buffer_size: 512,
            ip_filters: IpFilters::with_non_broadcast(),
        }
    }
}

#[allow(unused)]
impl StackBuilder {
    pub fn enable_udp(mut self, enable: bool) -> Self {
        self.enable_udp = enable;
        self
    }

    pub fn enable_tcp(mut self, enable: bool) -> Self {
        self.enable_tcp = enable;
        self
    }

    pub fn enable_icmp(mut self, enable: bool) -> Self {
        self.enable_icmp = enable;
        self
    }

    pub fn stack_buffer_size(mut self, size: usize) -> Self {
        self.stack_buffer_size = size;
        self
    }

    pub fn udp_buffer_size(mut self, size: usize) -> Self {
        self.udp_buffer_size = size;
        self
    }

    pub fn tcp_buffer_size(mut self, size: usize) -> Self {
        self.tcp_buffer_size = size;
        self
    }

    pub fn set_ip_filters(mut self, filters: IpFilters<'static>) -> Self {
        self.ip_filters = filters;
        self
    }

    pub fn add_ip_filter(mut self, filter: IpFilter<'static>) -> Self {
        self.ip_filters.add(filter);
        self
    }

    pub fn add_ip_filter_fn<F>(mut self, filter: F) -> Self
    where
        F: Fn(&IpAddr, &IpAddr) -> bool + Send + Sync + 'static,
    {
        self.ip_filters.add_fn(filter);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn build(
        self,
    ) -> std::io::Result<(
        Stack,
        Option<Runner>,
        Option<UdpSocket>,
        Option<TcpListener>,
    )> {
        let (stack_tx, stack_rx) = channel(self.stack_buffer_size);

        let (udp_tx, udp_rx) = if self.enable_udp {
            let (udp_tx, udp_rx) = channel(self.udp_buffer_size);
            (Some(udp_tx), Some(udp_rx))
        } else {
            (None, None)
        };

        let (tcp_tx, tcp_rx) = if self.enable_tcp {
            let (tcp_tx, tcp_rx) = channel(self.tcp_buffer_size);
            (Some(tcp_tx), Some(tcp_rx))
        } else {
            (None, None)
        };

        // ICMP is handled by TCP's Interface.
        // smoltcp's interface will always send replies to EchoRequest
        if self.enable_icmp && !self.enable_tcp {
            use std::io::{Error, ErrorKind::InvalidInput};
            return Err(Error::new(InvalidInput, "ICMP requires TCP"));
        }
        let icmp_tx = if self.enable_icmp {
            tcp_tx.clone()
        } else {
            None
        };

        let udp_socket = udp_rx.map(|udp_rx| UdpSocket::new(udp_rx, stack_tx.clone()));

        let (tcp_runner, tcp_listener) = if let Some(tcp_rx) = tcp_rx {
            let (tcp_runner, tcp_listener) = TcpListener::new(tcp_rx, stack_tx)?;
            (Some(tcp_runner), Some(tcp_listener))
        } else {
            (None, None)
        };

        let stack = Stack {
            ip_filters: self.ip_filters,
            stack_rx,
            sink_buf: None,
            udp_tx: udp_tx.map(PollSender::new),
            tcp_tx: tcp_tx.map(PollSender::new),
            icmp_tx: icmp_tx.map(PollSender::new),
        };

        Ok((stack, tcp_runner, udp_socket, tcp_listener))
    }
}

pub struct Stack {
    ip_filters: IpFilters<'static>,
    sink_buf: Option<(AnyIpPktFrame, IpProtocol)>,
    udp_tx: Option<PollSender<AnyIpPktFrame>>,
    tcp_tx: Option<PollSender<AnyIpPktFrame>>,
    icmp_tx: Option<PollSender<AnyIpPktFrame>>,
    stack_rx: Receiver<AnyIpPktFrame>,
}

impl Stack {
    pub async fn copy_bidirectional<T>(self, other: T) -> Result<(), Error>
    where
        T: Stream<Item = std::io::Result<AnyIpPktFrame>>
            + Sink<AnyIpPktFrame, Error = Error>
            + Unpin
            + Send
            + 'static,
    {
        let (mut stack_sink, mut stack_stream) = self.split();
        let (mut other_sink, mut other_stream) = other.split();

        tokio::select! {
            // Copy from stack to other
            result = async {
                while let Some(pkt) = stack_stream.next().await {
                    other_sink.send(pkt?).await?;
                }
                Ok(())
            } => result,

            // Copy from other to stack
            result = async {
                while let Some(pkt) = other_stream.next().await {
                    stack_sink.send(pkt?).await?;
                }
                Ok(())
            } => result,
        }
    }

    pub async fn copy_bidirectional_ignore_errors<T>(
        self,
        other: T,
        error_backoff: Option<Duration>,
    ) where
        T: Stream<Item = std::io::Result<AnyIpPktFrame>>
            + Sink<AnyIpPktFrame, Error = Error>
            + Unpin
            + Send
            + 'static,
    {
        let (mut stack_sink, mut stack_stream) = self.split();
        let (mut other_sink, mut other_stream) = other.split();

        macro_rules! handle_error {
            ($e:expr, $msg:expr) => {{
                debug!("{}: {}", $msg, $e);
                if let Some(duration) = error_backoff {
                    tokio::time::sleep(duration).await;
                }
            }};
        }

        tokio::select! {
            // Copy from stack to other
            _ = async {
                while let Some(pkt) = stack_stream.next().await {
                    match pkt {
                        Ok(frame) => {
                            if let Err(e) = other_sink.send(frame).await {
                                handle_error!(e, "Failed to send packet from stack to other");
                            }
                        }
                        Err(e) => {
                            handle_error!(e, "Failed to receive packet from stack");
                        }
                    }
                }
            } => {},

            // Copy from other to stack
            _ = async {
                while let Some(pkt) = other_stream.next().await {
                    match pkt {
                        Ok(frame) => {
                            if let Err(e) = stack_sink.send(frame).await {
                                handle_error!(e, "Failed to send packet from other to stack");
                            }
                        }
                        Err(e) => {
                            handle_error!(e, "Failed to receive packet from other");
                        }
                    }
                }
            } => {},
        }
    }

    /// Try to send the buffered packet to the appropriate channel.
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let Some((item, proto)) = self.sink_buf.take() else {
            return Poll::Ready(Ok(()));
        };

        let tx = match proto {
            IpProtocol::Tcp => self.tcp_tx.as_mut(),
            IpProtocol::Udp => self.udp_tx.as_mut(),
            IpProtocol::Icmp | IpProtocol::Icmpv6 => self.icmp_tx.as_mut(),
            _ => {
                debug!("Unexpected protocol in sink_buf: {:?}", proto);
                return Poll::Ready(Ok(()));
            }
        };

        let Some(tx) = tx else {
            // Channel is not enabled, drop the packet
            return Poll::Ready(Ok(()));
        };

        match tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => match tx.send_item(item) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(_) => Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "channel is closed"))),
            },
            Poll::Ready(Err(_)) => {
                Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "channel is closed")))
            }
            Poll::Pending => {
                // Channel not ready yet, put packet back to buffer
                self.sink_buf = Some((item, proto));
                Poll::Pending
            }
        }
    }
}

// Receive packets from stack
impl Stream for Stack {
    type Item = std::io::Result<AnyIpPktFrame>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.stack_rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => Poll::Ready(Some(Ok(pkt))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Send packets to stack
impl Sink<AnyIpPktFrame> for Stack {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.sink_buf.is_some() {
            match self.poll_send(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: AnyIpPktFrame) -> Result<(), Self::Error> {
        if item.is_empty() {
            return Ok(());
        }

        let packet = IpPacket::new_checked(item.as_slice()).map_err(|err| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("invalid IP packet: {}", err),
            )
        })?;

        let src_ip = packet.src_addr();
        let dst_ip = packet.dst_addr();

        let addr_allowed = self.ip_filters.is_allowed(&src_ip, &dst_ip);
        if !addr_allowed {
            trace!("IP packet {src_ip} -> {dst_ip} dropped by filter");
            return Ok(());
        }

        let protocol = packet.protocol();
        if matches!(
            protocol,
            IpProtocol::Tcp | IpProtocol::Udp | IpProtocol::Icmp | IpProtocol::Icmpv6
        ) {
            self.sink_buf = Some((item, protocol));
        } else {
            debug!("IP packet ignored (protocol: {:?})", protocol);
        }

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_send(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.stack_rx.close();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}
