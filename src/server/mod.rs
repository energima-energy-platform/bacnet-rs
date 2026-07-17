//! Hosted BACnet device support.
//!
//! The server side is split into a protocol-independent object service and a
//! BACnet/IP endpoint. [`ObjectService`] executes decoded BACnet operations
//! against an [`ObjectDatabase`], while [`BacnetIpServer`] owns the UDP socket
//! and handles BVLC, NPDU, and APDU framing.

mod bip;
mod dispatcher;
mod error;
mod object_service;

pub use bip::BacnetIpServer;
pub use dispatcher::{ServerDispatcher, ServerResponse};
pub use error::ServerError;
pub use object_service::ObjectService;
