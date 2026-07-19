use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// A trait combining the two async IO halves so streams of any flavor
/// (TCP, TLS, WS, AEAD-wrapped) can be boxed into one type.
pub trait IoStream: AsyncRead + AsyncWrite + Send {}

impl<T: AsyncRead + AsyncWrite + Send> IoStream for T {}

/// Every connection in the engine, post-handshake, is one of these.
pub type BoxedStream = Pin<Box<dyn IoStream>>;
