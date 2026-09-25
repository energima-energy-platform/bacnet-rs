use std::{
    io,
    net::{SocketAddr, UdpSocket},
};

/// What a BACnet/IP endpoint sends and receives datagrams through.
///
/// A device on an ordinary network uses a [`UdpSocket`]. The trait is for an
/// application that carries BACnet/IP some other way — through a socket it
/// shares with other traffic, a tunnel it terminates itself, or a harness that
/// feeds captured frames — while the stack keeps doing the framing.
///
/// Receiving blocks the way `UdpSocket::recv_from` does, including honouring
/// whatever read timeout the implementation has; the serve loops rely on a
/// timeout to notice they should stop.
pub trait DatagramSocket: Send + Sync {
    fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    fn send_to(&self, frame: &[u8], destination: SocketAddr) -> io::Result<usize>;

    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Allow sending to a broadcast address, which originating broadcast
    /// notifications needs. A transport with no such permission has nothing
    /// to do.
    fn set_broadcast(&self, _broadcast: bool) -> io::Result<()> {
        Ok(())
    }
}

impl DatagramSocket for UdpSocket {
    fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buffer)
    }

    fn send_to(&self, frame: &[u8], destination: SocketAddr) -> io::Result<usize> {
        UdpSocket::send_to(self, frame, destination)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        UdpSocket::local_addr(self)
    }

    fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        UdpSocket::set_broadcast(self, broadcast)
    }
}
