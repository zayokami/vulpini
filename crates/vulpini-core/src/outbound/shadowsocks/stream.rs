//! The Shadowsocks AEAD stream: salt + chunked AEAD framing over TCP.
//!
//! Wire layout (client -> server):
//!   [client salt][chunk][chunk]...
//! Server -> client is the same with the server's own salt.
//! Chunks: encrypted u16 length block, then encrypted payload block.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::node::SsMethod;
use crate::outbound::shadowsocks::crypto::{
    AeadCipher, LENGTH_BLOCK_LEN, MAX_PAYLOAD_LEN, TAG_LEN, derive_subkey, evp_bytes_to_key,
};

const READ_CHUNK: usize = 8192;

#[derive(Debug)]
enum ReadState {
    /// Waiting for the peer's salt (key_len bytes) to derive the decrypt key.
    Salt,
    /// Waiting for an encrypted length block (18 bytes).
    Length,
    /// Waiting for an encrypted payload block (len + 16 bytes).
    Data(usize),
}

/// A TCP stream wrapped in the Shadowsocks AEAD protocol (client side).
pub struct SsStream {
    inner: TcpStream,
    enc: AeadCipher,
    dec: Option<AeadCipher>,
    method: SsMethod,
    /// Kept to derive the decrypt subkey once the server salt arrives.
    master_key: Vec<u8>,
    rstate: ReadState,
    /// Raw ciphertext from the peer, not yet decrypted.
    ct_buf: BytesMut,
    /// Decrypted plaintext not yet consumed by the reader.
    plain: BytesMut,
    /// Encrypted bytes (starting with our salt) not yet written.
    wbuf: BytesMut,
}

impl SsStream {
    /// Wrap a freshly-connected TCP stream. The client salt is generated
    /// here and queued as the first bytes on the wire.
    pub fn new(inner: TcpStream, method: SsMethod, password: &str) -> Self {
        let master_key = evp_bytes_to_key(password.as_bytes(), method.key_len());
        let mut salt = vec![0u8; method.key_len()];
        rand::fill(&mut salt);

        let enc = AeadCipher::new(method, &derive_subkey(&salt, &master_key));

        let mut wbuf = BytesMut::with_capacity(salt.len() + 64);
        wbuf.extend_from_slice(&salt);

        SsStream {
            inner,
            enc,
            dec: None,
            method,
            master_key,
            rstate: ReadState::Salt,
            ct_buf: BytesMut::with_capacity(READ_CHUNK * 2),
            plain: BytesMut::with_capacity(READ_CHUNK),
            wbuf,
        }
    }

    fn bytes_needed(&self) -> usize {
        match self.rstate {
            ReadState::Salt => self.method.key_len(),
            ReadState::Length => LENGTH_BLOCK_LEN,
            ReadState::Data(len) => len + TAG_LEN,
        }
    }

    /// Process one complete block out of ct_buf. Returns Some(n) when
    /// plaintext became available (n bytes moved to `plain`).
    fn process_block(&mut self) -> io::Result<bool> {
        match self.rstate {
            ReadState::Salt => {
                let salt = self.ct_buf.split_to(self.method.key_len());
                let subkey = derive_subkey(&salt, &self.master_key);
                self.dec = Some(AeadCipher::new(self.method, &subkey));
                self.rstate = ReadState::Length;
                Ok(false)
            }
            ReadState::Length => {
                let block = self.ct_buf.split_to(LENGTH_BLOCK_LEN);
                let dec = self.dec.as_mut().expect("decrypt cipher initialized");
                let plain_len = dec.decrypt(&block).map_err(io::Error::other)?;
                let len = u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize;
                self.rstate = ReadState::Data(len);
                Ok(false)
            }
            ReadState::Data(len) => {
                let block = self.ct_buf.split_to(len + TAG_LEN);
                let dec = self.dec.as_mut().expect("decrypt cipher initialized");
                let data = dec.decrypt(&block).map_err(io::Error::other)?;
                self.plain.extend_from_slice(&data);
                self.rstate = ReadState::Length;
                Ok(true)
            }
        }
    }

    fn fill_plain(&mut self, buf: &mut ReadBuf<'_>) {
        let n = self.plain.len().min(buf.remaining());
        buf.put_slice(&self.plain[..n]);
        self.plain.advance(n);
    }

    /// Flush pending encrypted bytes to the inner stream.
    /// Poll::Pending means wbuf is still non-empty.
    fn poll_flush_wbuf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.wbuf.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.wbuf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write to shadowsocks stream",
                    )));
                }
                Poll::Ready(Ok(n)) => self.wbuf.advance(n),
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.plain.is_empty() {
            self.fill_plain(buf);
            return Poll::Ready(Ok(()));
        }

        loop {
            let need = self.bytes_needed();
            if self.ct_buf.len() >= need {
                if self.process_block()? {
                    self.fill_plain(buf);
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            // Not enough ciphertext for the next block: read more.
            let mut tmp = [0u8; READ_CHUNK];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        // EOF: clean only at a block boundary with nothing pending.
                        if self.ct_buf.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "shadowsocks stream ended mid-block",
                        )));
                    }
                    self.ct_buf.extend_from_slice(filled);
                }
            }
        }
    }
}

impl AsyncWrite for SsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Preserve ordering: earlier encrypted bytes go out first.
        match self.poll_flush_wbuf(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }

        for chunk in buf.chunks(MAX_PAYLOAD_LEN) {
            let len_block = self.enc.encrypt(&(chunk.len() as u16).to_be_bytes());
            let payload = self.enc.encrypt(chunk);
            self.wbuf.reserve(len_block.len() + payload.len());
            self.wbuf.extend_from_slice(&len_block);
            self.wbuf.extend_from_slice(&payload);
        }

        // The data is safely buffered; flush what we can right now.
        match self.poll_flush_wbuf(cx) {
            Poll::Pending => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_flush_wbuf(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_flush_wbuf(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
        }
    }
}
