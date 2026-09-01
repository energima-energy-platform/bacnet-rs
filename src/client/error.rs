//! Error types for the high-level BACnet client.
//!
//! The client returns a single, typed [`ClientError`] from all of its public
//! methods. This replaces the previous `Box<dyn std::error::Error>` returns and
//! lets callers match on specific failure modes (timeouts, protocol-level
//! rejects/aborts, per-property errors, etc.) instead of inspecting strings.

use crate::encoding::EncodingError;
use crate::service::{AbortReason, ErrorClass, ErrorCode, RejectReason};
use crate::util::describe_bacnet_error;
use thiserror::Error;

/// Errors returned by the synchronous and asynchronous high-level clients.
#[derive(Debug, Error)]
pub enum ClientError {
    /// An underlying socket / I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A request could not be encoded, or a response could not be decoded,
    /// using the BACnet encoding rules.
    #[error("encoding error: {0}")]
    Encoding(#[from] EncodingError),

    /// A response was malformed or could not be interpreted.
    #[error("failed to decode response: {0}")]
    Decode(String),

    /// No response was received within the configured timeout.
    #[error("request timed out")]
    Timeout,

    /// A response was expected but the peer returned nothing usable.
    #[error("no response from device")]
    NoResponse,

    /// The asynchronous client endpoint stopped before completing the request.
    #[error("BACnet client endpoint is closed")]
    EndpointClosed,

    /// Every BACnet invoke ID is currently assigned to an outstanding request.
    #[error("all BACnet invoke IDs are in use")]
    TooManyTransactions,

    /// The remote device rejected the request at the application layer.
    #[error("request rejected: {0}")]
    Rejected(RejectReason),

    /// The remote device aborted the transaction.
    #[error("transaction aborted: {0}")]
    Abort(AbortReason),

    /// The device returned a BACnet `Error` PDU (or a per-property error inside
    /// a ReadPropertyMultiple result), identified by its error class and code.
    ///
    /// Typed rather than numeric so a caller deciding what to do about a
    /// refusal matches on a name. The distinction usually matters: an
    /// [`ErrorCode::UnknownObject`] means the point is gone and asking again
    /// is pointless, while a resource error means the device was merely busy.
    /// Codes this crate does not name still round-trip through the enums'
    /// `Reserved`/`Custom` arms, so nothing a device can say is lost.
    #[error("{}", describe_bacnet_error(*class, *code))]
    PropertyError {
        /// BACnet error class.
        class: ErrorClass,
        /// BACnet error code.
        code: ErrorCode,
    },

    /// A supplied address could not be parsed or resolved.
    #[error("invalid address: {0}")]
    AddressParse(String),
}
