use std::io;

use thiserror::Error;

use crate::{
    app::ApplicationError, encoding::EncodingError, network::NetworkError, object::ObjectError,
};

/// Errors returned while serving a hosted BACnet device.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("encoding error: {0}")]
    Encoding(#[from] EncodingError),

    #[error("application-layer error: {0}")]
    Application(#[from] ApplicationError),

    #[error("network-layer error: {0}")]
    Network(#[from] NetworkError),

    #[error("hosted object error: {0}")]
    Object(#[from] ObjectError),
}
