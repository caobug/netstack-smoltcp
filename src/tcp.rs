use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use futures::Stream;
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::Device,
    socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState},
    storage::RingBuffer,
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv6Address, TcpPacket},
};
use spin::Mutex as SpinMutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{
        mpsc::{unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender},
        Notify,
    },
};
use tracing::{error, trace, warn};

use crate::{
    device::VirtualDevice,
    packet::{AnyIpPktFrame, IpPacket},
    Runner,
};

const BUFFER_SIZE: usize = 16383;
const KEEPALIVE_SECS: u64 = 28;
const SOCKET_TIMEOUT_SECS: u64 = 7200;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SocketState {
    Active,
    Closing,
    Closed,
}

struct SocketControl {
    send_buffer: RingBuffer<'static, u8>,
    recv_buffer: RingBuffer<'static, u8>,
    send_waker: Option<Waker>,
    recv_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    send_state: SocketState,
    recv_state: SocketState,
}

impl SocketControl {
    fn new() -> Self {
        Self {
            send_buffer: RingBuffer::new(vec![0u8; BUFFER_SIZE]),
            recv_buffer: RingBuffer::new(vec![0u8; BUFFER_SIZE]),
            send_waker: None,
            recv_waker: None,
            shutdown_waker: None,
            send_state: SocketState::Active,
            recv_state: SocketState::Active,
        }
    }

    fn wake_sender(&mut self) {
        if let Some(waker) = self.send_waker.take() {
            waker.wake();
        }
    }

    fn wake_receiver(&mut self) {
        if let Some(waker) = self.recv_waker.take() {
            waker.wake();
        }
    }

    fn wake_shutdown(&mut self) {
        if let Some(waker) = self.shutdown_waker.take() {
            waker.wake();
        }
    }

    fn close(&mut self) {
        self.send_state = SocketState::Closed;
        self.recv_state = SocketState::Closed;
        self.wake_sender();
        self.wake_receiver();
        self.wake_shutdown();
    }

    fn ready_to_initiate_close(&self) -> bool {
        matches!(self.send_state, SocketState::Closing) && self.send_buffer.is_empty()
    }

    fn is_stream_dropped(&self) -> bool {
        matches!(self.send_state, SocketState::Closed)
            && matches!(self.recv_state, SocketState::Closed)
    }
}

struct NewConnection {
    control: SharedControl,
    socket: TcpSocket<'static>,
}

type SharedNotify = Arc<Notify>;
type SharedControl = Arc<SpinMutex<SocketControl>>;

struct TcpListenerRunner;

impl TcpListenerRunner {
    fn create(
        device: VirtualDevice,
        iface: Interface,
        iface_tx: UnboundedSender<Vec<u8>>,
        tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: UnboundedSender<TcpStream>,
        sockets: HashMap<SocketHandle, SharedControl>,
    ) -> Runner {
        Runner::new(async move {
            let notify = Arc::new(Notify::new());
            let (conn_tx, conn_rx) = unbounded_channel::<NewConnection>();

            let packet_handler =
                Self::handle_packets(notify.clone(), iface_tx, tcp_rx, stream_tx, conn_tx);

            let socket_handler = Self::handle_sockets(notify, device, iface, sockets, conn_rx);

            tokio::select! {
                result = packet_handler => result,
                result = socket_handler => result,
            }?;

            trace!("TCP listener exited");
            Ok(())
        })
    }

    async fn handle_packets(
        notify: SharedNotify,
        iface_tx: UnboundedSender<Vec<u8>>,
        mut tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: UnboundedSender<TcpStream>,
        conn_tx: UnboundedSender<NewConnection>,
    ) -> std::io::Result<()> {
        while let Some(frame) = tcp_rx.recv().await {
            let packet = match IpPacket::<&[u8]>::new_checked(frame.as_slice()) {
                Ok(p) => p,
                Err(e) => {
                    warn!("Invalid IP packet: {}", e);
                    continue;
                }
            };

            if matches!(packet.protocol(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
                Self::forward_packet(&iface_tx, &notify, frame)?;
                continue;
            }

            let (src_addr, dst_addr, tcp_packet) = match Self::parse_tcp_packet(&packet) {
                Ok(result) => result,
                Err(_) => continue,
            };

            if tcp_packet.syn() && !tcp_packet.ack() {
                let connection = Self::create_connection(dst_addr)?;
                let stream = TcpStream::new(
                    src_addr,
                    dst_addr,
                    notify.clone(),
                    connection.control.clone(),
                );

                stream_tx
                    .send(stream)
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
                conn_tx
                    .send(connection)
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
            }

            Self::forward_packet(&iface_tx, &notify, frame)?;
        }
        Ok(())
    }

    fn parse_tcp_packet<'a>(
        packet: &'a IpPacket<&'a [u8]>,
    ) -> Result<(SocketAddr, SocketAddr, TcpPacket<&'a [u8]>), ()> {
        let tcp_packet = TcpPacket::new_checked(packet.payload()).map_err(|_| ())?;
        let src_addr = SocketAddr::new(packet.src_addr(), tcp_packet.src_port());
        let dst_addr = SocketAddr::new(packet.dst_addr(), tcp_packet.dst_port());
        Ok((src_addr, dst_addr, tcp_packet))
    }

    fn create_connection(dst_addr: SocketAddr) -> std::io::Result<NewConnection> {
        let mut socket = TcpSocket::new(
            TcpSocketBuffer::new(vec![0u8; BUFFER_SIZE]),
            TcpSocketBuffer::new(vec![0u8; BUFFER_SIZE]),
        );

        socket.set_keep_alive(Some(Duration::from_secs(KEEPALIVE_SECS)));
        socket.set_timeout(Some(Duration::from_secs(SOCKET_TIMEOUT_SECS)));
        socket.set_nagle_enabled(false);

        socket.listen(dst_addr).map_err(|e| {
            error!("Listen failed: {}", e);
            std::io::Error::from(std::io::ErrorKind::ConnectionRefused)
        })?;

        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        Ok(NewConnection { control, socket })
    }

    fn forward_packet(
        iface_tx: &UnboundedSender<Vec<u8>>,
        notify: &SharedNotify,
        frame: Vec<u8>,
    ) -> std::io::Result<()> {
        iface_tx
            .send(frame)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        notify.notify_one();
        Ok(())
    }

    async fn handle_sockets(
        notify: SharedNotify,
        mut device: VirtualDevice,
        mut iface: Interface,
        mut sockets: HashMap<SocketHandle, SharedControl>,
        mut conn_rx: UnboundedReceiver<NewConnection>,
    ) -> std::io::Result<()> {
        let mut socket_set = SocketSet::new(vec![]);

        loop {
            while let Ok(NewConnection { control, socket }) = conn_rx.try_recv() {
                let handle = socket_set.add(socket);
                sockets.insert(handle, control);
            }

            let poll_start = Instant::now();
            iface.poll(poll_start, &mut device, &mut socket_set);

            let closed_sockets = Self::process_sockets(&mut socket_set, &mut sockets);

            for handle in closed_sockets {
                sockets.remove(&handle);
                socket_set.remove(handle);
            }

            let next_duration = iface
                .poll_delay(poll_start, &socket_set)
                .unwrap_or(Duration::from_millis(10));

            if next_duration != Duration::ZERO {
                let _ = tokio::time::timeout(
                    tokio::time::Duration::from_micros(next_duration.total_micros()),
                    notify.notified(),
                )
                .await;
            }
        }
    }

    fn process_sockets(
        socket_set: &mut SocketSet,
        sockets: &mut HashMap<SocketHandle, SharedControl>,
    ) -> Vec<SocketHandle> {
        let mut closed_sockets = Vec::new();

        for (&handle, control) in sockets.iter() {
            let socket = socket_set.get_mut::<TcpSocket>(handle);
            let mut ctrl = control.lock();

            if socket.state() == TcpState::Closed {
                ctrl.close();
                closed_sockets.push(handle);
                continue;
            }

            Self::handle_application_close(&mut ctrl, socket);

            if Self::should_force_cleanup(&ctrl, socket) {
                socket.abort();
                ctrl.close();
                closed_sockets.push(handle);
                continue;
            }

            Self::handle_socket_read(&mut ctrl, socket);
            Self::handle_socket_write(&mut ctrl, socket);
            Self::sync_control_state(&mut ctrl, socket);
        }

        closed_sockets
    }

    fn handle_application_close(ctrl: &mut SocketControl, socket: &mut TcpSocket<'_>) {
        let should_initiate_close = match ctrl.send_state {
            SocketState::Closing => ctrl.send_buffer.is_empty(),
            SocketState::Closed => ctrl.is_stream_dropped(),
            SocketState::Active => socket.state() == TcpState::CloseWait,
        };

        if should_initiate_close && socket.may_send() {
            socket.close();
        }
    }

    fn should_force_cleanup(ctrl: &SocketControl, socket: &TcpSocket<'_>) -> bool {
        ctrl.is_stream_dropped() && !socket.may_send()
    }

    fn sync_control_state(ctrl: &mut SocketControl, socket: &TcpSocket<'_>) {
        if matches!(ctrl.send_state, SocketState::Closing) && !socket.may_send() {
            ctrl.send_state = SocketState::Closed;
            ctrl.wake_shutdown();
        }
    }

    fn handle_socket_read(ctrl: &mut SocketControl, socket: &mut TcpSocket<'_>) {
        let mut should_wake = false;

        while socket.can_recv() && !ctrl.recv_buffer.is_full() {
            match socket.recv(|data| {
                let bytes_read = ctrl.recv_buffer.enqueue_slice(data);
                (bytes_read, ())
            }) {
                Ok(_) => should_wake = true,
                Err(e) => {
                    error!("Socket read error: {}", e);
                    ctrl.recv_state = SocketState::Closed;
                    should_wake = true;
                    break;
                }
            }
        }

        if matches!(ctrl.recv_state, SocketState::Active)
            && !socket.may_recv()
            && ctrl.recv_buffer.is_empty()
        {
            let in_handshake = matches!(
                socket.state(),
                TcpState::Listen | TcpState::SynSent | TcpState::SynReceived
            );

            if !in_handshake {
                ctrl.recv_state = SocketState::Closed;
                should_wake = true;
            }
        }

        if should_wake {
            ctrl.wake_receiver();
        }
    }

    fn handle_socket_write(ctrl: &mut SocketControl, socket: &mut TcpSocket<'_>) {
        let mut should_wake_sender = false;
        let mut should_wake_shutdown = false;

        while socket.can_send() && !ctrl.send_buffer.is_empty() {
            match socket.send(|buffer| {
                let bytes_sent = ctrl.send_buffer.dequeue_slice(buffer);
                (bytes_sent, ())
            }) {
                Ok(_) => should_wake_sender = true,
                Err(e) => {
                    error!("Socket write error: {}", e);
                    ctrl.send_state = SocketState::Closed;
                    should_wake_sender = true;
                    should_wake_shutdown = true;
                    break;
                }
            }
        }

        if should_wake_sender {
            ctrl.wake_sender();
        }

        if should_wake_shutdown || ctrl.ready_to_initiate_close() {
            ctrl.wake_shutdown();
        }
    }
}

pub struct TcpListener {
    stream_rx: UnboundedReceiver<TcpStream>,
}

impl TcpListener {
    pub(super) fn new(
        tcp_rx: Receiver<AnyIpPktFrame>,
        stack_tx: Sender<AnyIpPktFrame>,
    ) -> std::io::Result<(Runner, Self)> {
        let (mut device, iface_tx) = VirtualDevice::new(stack_tx);
        let iface = Self::create_interface(&mut device)?;
        let (stream_tx, stream_rx) = unbounded_channel();

        let runner =
            TcpListenerRunner::create(device, iface, iface_tx, tcp_rx, stream_tx, HashMap::new());

        Ok((runner, Self { stream_rx }))
    }

    fn create_interface<D>(device: &mut D) -> std::io::Result<Interface>
    where
        D: Device + ?Sized,
    {
        let mut config = InterfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = rand::random();

        let mut iface = Interface::new(config, device, Instant::now());

        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0))
                .expect("Failed to add IPv4 address");
            addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0))
                .expect("Failed to add IPv6 address");
        });

        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;

        iface.set_any_ip(true);
        Ok(iface)
    }
}

impl Stream for TcpListener {
    type Item = (TcpStream, SocketAddr, SocketAddr);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream_rx.poll_recv(cx).map(|opt| {
            opt.map(|stream| {
                let local = stream.src_addr;
                let remote = stream.dst_addr;
                (stream, local, remote)
            })
        })
    }
}

pub struct TcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    notify: SharedNotify,
    control: SharedControl,
}

impl TcpStream {
    fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        notify: SharedNotify,
        control: SharedControl,
    ) -> Self {
        Self {
            src_addr,
            dst_addr,
            notify,
            control,
        }
    }

    fn register_waker(waker_slot: &mut Option<Waker>, cx: &Context<'_>) {
        if waker_slot
            .as_ref()
            .map_or(true, |w| !w.will_wake(cx.waker()))
        {
            *waker_slot = Some(cx.waker().clone());
        }
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut ctrl = self.control.lock();

        if matches!(ctrl.send_state, SocketState::Active) {
            ctrl.send_state = if ctrl.send_buffer.is_empty() {
                SocketState::Closed
            } else {
                SocketState::Closing
            };
        }

        if matches!(ctrl.recv_state, SocketState::Active) {
            ctrl.recv_state = SocketState::Closed;
        }

        ctrl.wake_sender();
        ctrl.wake_receiver();
        ctrl.wake_shutdown();

        self.notify.notify_one();
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut ctrl = self.control.lock();

        if ctrl.recv_buffer.is_empty() {
            if matches!(ctrl.recv_state, SocketState::Closed) {
                return Poll::Ready(Ok(()));
            }

            Self::register_waker(&mut ctrl.recv_waker, cx);
            return Poll::Pending;
        }

        let unfilled = buf.initialize_unfilled();
        let bytes_read = ctrl.recv_buffer.dequeue_slice(unfilled);
        buf.advance(bytes_read);

        if bytes_read > 0 {
            self.notify.notify_one();
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut ctrl = self.control.lock();

        if !matches!(ctrl.send_state, SocketState::Active) {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }

        if ctrl.send_buffer.is_full() {
            Self::register_waker(&mut ctrl.send_waker, cx);
            return Poll::Pending;
        }

        let bytes_written = ctrl.send_buffer.enqueue_slice(buf);

        if bytes_written > 0 {
            self.notify.notify_one();
        }

        Poll::Ready(Ok(bytes_written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut ctrl = self.control.lock();

        if matches!(ctrl.send_state, SocketState::Closed) {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }

        if !ctrl.send_buffer.is_empty() {
            Self::register_waker(&mut ctrl.send_waker, cx);
            return Poll::Pending;
        }

        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut ctrl = self.control.lock();

        match ctrl.send_state {
            SocketState::Closed => return Poll::Ready(Ok(())),
            SocketState::Closing => {}
            SocketState::Active => ctrl.send_state = SocketState::Closing,
        }

        Self::register_waker(&mut ctrl.shutdown_waker, cx);
        self.notify.notify_one();

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_socket_control_new() {
        let ctrl = SocketControl::new();
        assert_eq!(ctrl.send_state, SocketState::Active);
        assert_eq!(ctrl.recv_state, SocketState::Active);
        assert!(ctrl.send_waker.is_none());
        assert!(ctrl.recv_waker.is_none());
        assert!(ctrl.shutdown_waker.is_none());
    }

    #[test]
    fn test_socket_control_close() {
        let mut ctrl = SocketControl::new();
        ctrl.close();
        assert_eq!(ctrl.send_state, SocketState::Closed);
        assert_eq!(ctrl.recv_state, SocketState::Closed);
    }

    #[test]
    fn test_socket_control_ready_to_initiate_close() {
        let mut ctrl = SocketControl::new();

        assert!(!ctrl.ready_to_initiate_close());

        ctrl.send_state = SocketState::Closing;
        assert!(ctrl.ready_to_initiate_close());

        _ = ctrl.send_buffer.enqueue_slice(&[1, 2, 3]);
        assert!(!ctrl.ready_to_initiate_close());
    }

    #[tokio::test]
    async fn test_tcp_stream_write_when_active() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control.clone(),
        );

        let mut stream = stream;
        let data = b"test data";

        match stream.write(data).await {
            Ok(n) => {
                assert_eq!(n, data.len());
                let ctrl = control.lock();
                assert_eq!(ctrl.send_buffer.len(), data.len());
            }
            Err(e) => panic!("Write failed: {}", e),
        }
    }

    #[tokio::test]
    async fn test_tcp_stream_write_when_closed() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        {
            let mut ctrl = control.lock();
            ctrl.send_state = SocketState::Closed;
        }

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control,
        );

        let mut stream = stream;
        let data = b"test data";

        match stream.write(data).await {
            Ok(_) => panic!("Should have returned error"),
            Err(e) => assert_eq!(e.kind(), ErrorKind::BrokenPipe),
        }
    }

    #[tokio::test]
    async fn test_tcp_stream_read_eof() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        {
            let mut ctrl = control.lock();
            ctrl.recv_state = SocketState::Closed;
        }

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control,
        );

        let mut stream = stream;
        let mut buf = vec![0u8; 1024];

        match stream.read(&mut buf).await {
            Ok(n) => assert_eq!(n, 0),
            Err(e) => panic!("Read failed: {}", e),
        }
    }

    #[tokio::test]
    async fn test_tcp_stream_read_with_data() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        let test_data = b"hello world";
        {
            let mut ctrl = control.lock();
            _ = ctrl.recv_buffer.enqueue_slice(test_data);
        }

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control,
        );

        let mut stream = stream;
        let mut buf = vec![0u8; 1024];

        match stream.read(&mut buf).await {
            Ok(n) => {
                assert_eq!(n, test_data.len());
                assert_eq!(&buf[..n], test_data);
            }
            Err(e) => panic!("Read failed: {}", e),
        }
    }

    #[tokio::test]
    async fn test_tcp_stream_read_buffered_data_then_eof() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        let test_data = b"buffered";
        {
            let mut ctrl = control.lock();
            _ = ctrl.recv_buffer.enqueue_slice(test_data);
            ctrl.recv_state = SocketState::Closed;
        }

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control.clone(),
        );

        let mut stream = stream;
        let mut buf = vec![0u8; 1024];

        let n1 = stream.read(&mut buf).await.unwrap();
        assert_eq!(n1, test_data.len());
        assert_eq!(&buf[..n1], test_data);

        let n2 = stream.read(&mut buf).await.unwrap();
        assert_eq!(n2, 0);
    }

    #[tokio::test]
    async fn test_tcp_stream_flush_success() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control,
        );

        let mut stream = stream;
        stream.flush().await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_stream_flush_when_closed() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        {
            let mut ctrl = control.lock();
            ctrl.send_state = SocketState::Closed;
        }

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control,
        );

        let mut stream = stream;
        match stream.flush().await {
            Ok(_) => panic!("Should have returned error"),
            Err(e) => assert_eq!(e.kind(), ErrorKind::BrokenPipe),
        }
    }

    #[tokio::test]
    async fn test_tcp_stream_shutdown_from_active() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify.clone(),
            control.clone(),
        );

        let mut stream = stream;

        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            let mut ctrl = control.lock();
            ctrl.send_state = SocketState::Closed;
            ctrl.wake_shutdown();
        });

        stream.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_stream_shutdown_when_already_closed() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        {
            let mut ctrl = control.lock();
            ctrl.send_state = SocketState::Closed;
        }

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control,
        );

        let mut stream = stream;
        stream.shutdown().await.unwrap();
    }

    #[test]
    fn test_tcp_stream_drop_sets_closing_state() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        {
            let _stream = TcpStream::new(
                "127.0.0.1:8080".parse().unwrap(),
                "127.0.0.1:9090".parse().unwrap(),
                notify,
                control.clone(),
            );
        }

        let ctrl = control.lock();
        assert_eq!(ctrl.send_state, SocketState::Closed);
        assert_eq!(ctrl.recv_state, SocketState::Closed);
    }

    #[test]
    fn test_register_waker_replaces_different_waker() {
        use std::task::{Context, RawWaker, RawWakerVTable, Waker};

        unsafe fn clone_raw(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        unsafe fn wake_raw(_: *const ()) {}
        unsafe fn wake_by_ref_raw(_: *const ()) {}
        unsafe fn drop_raw(_: *const ()) {}

        static VTABLE: RawWakerVTable =
            RawWakerVTable::new(clone_raw, wake_raw, wake_by_ref_raw, drop_raw);

        let raw_waker = RawWaker::new(std::ptr::null(), &VTABLE);
        let waker1 = unsafe { Waker::from_raw(raw_waker) };

        let raw_waker2 = RawWaker::new(std::ptr::null(), &VTABLE);
        let waker2 = unsafe { Waker::from_raw(raw_waker2) };

        let mut waker_slot = Some(waker1);
        let ctx = Context::from_waker(&waker2);

        TcpStream::register_waker(&mut waker_slot, &ctx);
        assert!(waker_slot.is_some());
    }

    #[tokio::test]
    async fn test_concurrent_read_write() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        let test_data = b"concurrent test";
        {
            let mut ctrl = control.lock();
            _ = ctrl.recv_buffer.enqueue_slice(test_data);
        }

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify.clone(),
            control.clone(),
        );

        let mut stream = stream;

        let mut buf = vec![0u8; 1024];
        let read_result = stream.read(&mut buf).await.unwrap();
        assert_eq!(read_result, test_data.len());
        assert_eq!(&buf[..read_result], test_data);

        let test_data = b"write data";
        let write_result = stream.write(test_data).await.unwrap();
        assert_eq!(write_result, test_data.len());

        let ctrl = control.lock();
        assert_eq!(ctrl.send_buffer.len(), 10);
    }

    #[tokio::test]
    async fn test_write_to_full_buffer_then_drain() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify.clone(),
            control.clone(),
        );

        let mut stream = stream;
        let large_data = vec![1u8; BUFFER_SIZE];

        let n1 = stream.write(&large_data).await.unwrap();
        assert_eq!(n1, BUFFER_SIZE);

        {
            let ctrl = control.lock();
            assert!(ctrl.send_buffer.is_full());
        }

        {
            let mut ctrl = control.lock();
            let mut drain = vec![0u8; BUFFER_SIZE];
            let drained = ctrl.send_buffer.dequeue_slice(&mut drain);
            assert_eq!(drained, BUFFER_SIZE);
        }

        let test_data = b"after drain";
        let n2 = stream.write(test_data).await.unwrap();
        assert_eq!(n2, test_data.len());
    }

    #[tokio::test]
    async fn test_multiple_small_writes() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control.clone(),
        );

        let mut stream = stream;

        for i in 0..10 {
            let data = format!("write {}", i);
            stream.write(data.as_bytes()).await.unwrap();
        }

        let ctrl = control.lock();
        assert!(ctrl.send_buffer.len() > 0);
    }

    #[tokio::test]
    async fn test_read_partial_data() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        let full_data = b"0123456789abcdefghij";
        {
            let mut ctrl = control.lock();
            _ = ctrl.recv_buffer.enqueue_slice(full_data);
        }

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control.clone(),
        );

        let mut stream = stream;
        let mut buf = vec![0u8; 10];

        let n1 = stream.read(&mut buf).await.unwrap();
        assert_eq!(n1, 10);
        assert_eq!(&buf[..n1], &full_data[..10]);

        let n2 = stream.read(&mut buf).await.unwrap();
        assert_eq!(n2, 10);
        assert_eq!(&buf[..n2], &full_data[10..]);
    }

    #[tokio::test]
    async fn test_shutdown_with_pending_data() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        {
            let mut ctrl = control.lock();
            _ = ctrl.send_buffer.enqueue_slice(b"pending data");
        }

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify.clone(),
            control.clone(),
        );

        let mut stream = stream;

        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            let mut ctrl = control.lock();
            let mut drain = vec![0u8; 100];
            _ = ctrl.send_buffer.dequeue_slice(&mut drain);
            ctrl.send_state = SocketState::Closed;
            ctrl.wake_shutdown();
        });

        stream.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_write_after_drop_another_stream() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        let stream1 = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify.clone(),
            control.clone(),
        );

        drop(stream1);

        let ctrl = control.lock();
        assert_eq!(ctrl.send_state, SocketState::Closed);
        assert_eq!(ctrl.recv_state, SocketState::Closed);
    }

    #[tokio::test]
    async fn test_read_write_sequence() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control.clone(),
        );

        let mut stream = stream;

        let write_data = b"step1";
        stream.write(write_data).await.unwrap();

        {
            let mut ctrl = control.lock();
            assert_eq!(ctrl.send_buffer.len(), write_data.len());
            _ = ctrl.send_buffer.dequeue_slice(&mut vec![0u8; 100]);
        }

        {
            let mut ctrl = control.lock();
            _ = ctrl.recv_buffer.enqueue_slice(b"step2");
        }

        let mut buf = vec![0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"step2");
    }

    #[tokio::test]
    async fn test_empty_write() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control.clone(),
        );

        let mut stream = stream;
        let n = stream.write(b"").await.unwrap();
        assert_eq!(n, 0);

        let ctrl = control.lock();
        assert_eq!(ctrl.send_buffer.len(), 0);
    }

    #[tokio::test]
    async fn test_write_closing_state() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        {
            let mut ctrl = control.lock();
            ctrl.send_state = SocketState::Closing;
        }

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control,
        );

        let mut stream = stream;
        match stream.write(b"test").await {
            Ok(_) => panic!("Should have returned error"),
            Err(e) => assert_eq!(e.kind(), ErrorKind::BrokenPipe),
        }
    }

    #[test]
    fn test_socket_control_wake_methods_with_no_waker() {
        let mut ctrl = SocketControl::new();
        ctrl.wake_sender();
        ctrl.wake_receiver();
        ctrl.wake_shutdown();
    }

    #[test]
    fn test_socket_control_multiple_close_calls() {
        let mut ctrl = SocketControl::new();
        ctrl.close();
        ctrl.close();
        assert_eq!(ctrl.send_state, SocketState::Closed);
        assert_eq!(ctrl.recv_state, SocketState::Closed);
    }

    #[tokio::test]
    async fn test_flush_with_pending_data() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        {
            let mut ctrl = control.lock();
            _ = ctrl.send_buffer.enqueue_slice(b"pending");
        }

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify.clone(),
            control.clone(),
        );

        let mut stream = stream;

        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            let mut ctrl = control.lock();
            let mut drain = vec![0u8; 100];
            _ = ctrl.send_buffer.dequeue_slice(&mut drain);
            ctrl.wake_sender();
        });

        stream.flush().await.unwrap();
    }

    #[tokio::test]
    async fn test_read_exact_buffer_size() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        let data = vec![42u8; BUFFER_SIZE];
        {
            let mut ctrl = control.lock();
            _ = ctrl.recv_buffer.enqueue_slice(&data);
        }

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control,
        );

        let mut stream = stream;
        let mut buf = vec![0u8; BUFFER_SIZE + 100];

        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, BUFFER_SIZE);
        assert_eq!(&buf[..n], &data[..]);
    }

    #[tokio::test]
    async fn test_multiple_reads_until_eof() {
        let control = Arc::new(SpinMutex::new(SocketControl::new()));
        let notify = Arc::new(Notify::new());

        {
            let mut ctrl = control.lock();
            _ = ctrl.recv_buffer.enqueue_slice(b"chunk1");
            ctrl.recv_state = SocketState::Closed;
        }

        let stream = TcpStream::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            notify,
            control,
        );

        let mut stream = stream;
        let mut total = Vec::new();
        let mut buf = vec![0u8; 100];

        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total.extend_from_slice(&buf[..n]);
        }

        assert_eq!(total, b"chunk1");
    }
}
