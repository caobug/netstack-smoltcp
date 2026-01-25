use smoltcp::phy::Checksum;
use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc::{unbounded_channel, Permit, Sender, UnboundedReceiver, UnboundedSender};

use crate::packet::AnyIpPktFrame;

pub(super) struct VirtualDevice {
    in_buf: UnboundedReceiver<Vec<u8>>,
    out_buf: Sender<AnyIpPktFrame>,
}

impl VirtualDevice {
    pub(super) fn new(iface_egress_tx: Sender<AnyIpPktFrame>) -> (Self, UnboundedSender<Vec<u8>>) {
        let (iface_ingress_tx, iface_ingress_rx) = unbounded_channel();
        (
            Self {
                in_buf: iface_ingress_rx,
                out_buf: iface_egress_tx,
            },
            iface_ingress_tx,
        )
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let permit = self.out_buf.try_reserve().ok()?;
        let buffer = self.in_buf.try_recv().ok()?;
        Some((Self::RxToken { buffer }, Self::TxToken { permit }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.out_buf
            .try_reserve()
            .ok()
            .map(|permit| Self::TxToken { permit })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1504;
        capabilities.checksum.ipv4 = Checksum::Tx;
        capabilities.checksum.udp = Checksum::Tx;
        capabilities.checksum.tcp = Checksum::Tx;
        capabilities.checksum.icmpv4 = Checksum::Tx;
        capabilities.checksum.icmpv6 = Checksum::Tx;
        capabilities
    }
}

pub(super) struct VirtualRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&mut self.buffer[..])
    }
}

pub(super) struct VirtualTxToken<'a> {
    permit: Permit<'a, Vec<u8>>,
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.permit.send(buffer);
        result
    }
}
