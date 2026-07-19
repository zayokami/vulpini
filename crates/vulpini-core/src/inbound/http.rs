use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{Address, BoxedStream, CoreError, parse_host_port};

pub const TAG: &str = "http";

const MAX_HEADER: usize = 8192;
const OK_RESPONSE: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

/// Read an HTTP CONNECT request. Only CONNECT is supported — plain
/// forward-proxy requests are rejected (use the SOCKS5 port instead).
pub async fn handshake(stream: &mut BoxedStream) -> Result<Address, CoreError> {
    let header = read_until_header_end(stream).await?;
    let text = String::from_utf8(header)
        .map_err(|_| CoreError::Protocol("CONNECT header is not utf-8".into()))?;

    let request_line = text
        .lines()
        .next()
        .ok_or_else(|| CoreError::Protocol("empty request".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let authority = parts.next().unwrap_or("");

    if !method.eq_ignore_ascii_case("CONNECT") {
        reply_err(
            stream,
            &CoreError::Unsupported("only CONNECT is supported".into()),
        )
        .await
        .ok();
        return Err(CoreError::Unsupported(format!(
            "http method '{method}' not supported"
        )));
    }

    let (host, port) = split_authority(authority)?;
    Ok(parse_host_port(&host, port))
}

fn split_authority(authority: &str) -> Result<(String, u16), CoreError> {
    // Handles "host:port" and "[v6]:port".
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| CoreError::Protocol(format!("bad authority '{authority}'")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| CoreError::Protocol(format!("bad port in '{authority}'")))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(CoreError::Protocol("empty host".into()));
    }
    Ok((host.to_string(), port))
}

async fn read_until_header_end(stream: &mut BoxedStream) -> Result<Vec<u8>, CoreError> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() >= MAX_HEADER {
            return Err(CoreError::Protocol("CONNECT header too large".into()));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(CoreError::Protocol(
                "connection closed during header".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

pub async fn reply_ok(stream: &mut BoxedStream) -> Result<(), CoreError> {
    stream.write_all(OK_RESPONSE).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn reply_err(stream: &mut BoxedStream, err: &CoreError) -> Result<(), CoreError> {
    let (code, reason) = match err {
        CoreError::Blocked => (403, "Forbidden"),
        CoreError::Unsupported(_) => (405, "Method Not Allowed"),
        _ => (502, "Bad Gateway"),
    };
    let body = format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\n\r\n");
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn connect_domain() {
        let (client, server) = duplex(2048);
        let mut server: BoxedStream = Box::pin(server);
        let mut client = client;

        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client
                .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                .await
                .unwrap();
        });

        let addr = handshake(&mut server).await.unwrap();
        assert_eq!(addr, Address::Domain("example.com".into(), 443));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn connect_ipv6_authority() {
        let (client, server) = duplex(2048);
        let mut server: BoxedStream = Box::pin(server);
        let mut client = client;

        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client
                .write_all(b"CONNECT [::1]:8080 HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
        });

        let addr = handshake(&mut server).await.unwrap();
        assert_eq!(
            addr,
            "[::1]:8080".parse::<std::net::SocketAddr>().unwrap().into()
        );
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn plain_get_rejected() {
        let (client, server) = duplex(2048);
        let mut server: BoxedStream = Box::pin(server);
        let mut client = client;

        let writer = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            client
                .write_all(b"GET http://example.com/ HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            let mut buf = vec![0u8; 64];
            let n = client.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).contains("405"));
        });

        assert!(matches!(
            handshake(&mut server).await,
            Err(CoreError::Unsupported(_))
        ));
        writer.await.unwrap();
    }
}
