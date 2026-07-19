use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{Address, BoxedStream, CoreError, parse_host_port};

pub const TAG: &str = "socks5";

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

/// Read the SOCKS5 greeting + request. Returns the target address.
/// No authentication is offered (local inbound only).
pub async fn handshake(stream: &mut BoxedStream) -> Result<Address, CoreError> {
    // Greeting: VER NMETHODS METHODS...
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(CoreError::Protocol(format!(
            "bad socks version {:#x}",
            head[0]
        )));
    }
    let nmethods = head[1] as usize;
    if nmethods == 0 {
        return Err(CoreError::Protocol("no auth methods offered".into()));
    }
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[VER, 0xFF]).await.ok();
        return Err(CoreError::Protocol(
            "client does not offer no-auth method".into(),
        ));
    }
    stream.write_all(&[VER, 0x00]).await?;

    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != VER {
        return Err(CoreError::Protocol("bad request version".into()));
    }
    if req[1] != CMD_CONNECT {
        // UDP ASSOCIATE and BIND arrive here; only CONNECT is supported.
        reply(stream, REP_CMD_NOT_SUPPORTED).await.ok();
        return Err(CoreError::Unsupported(format!(
            "socks5 command {:#x} not supported",
            req[1]
        )));
    }

    let target = read_address(stream, req[3]).await?;
    Ok(target)
}

async fn read_address(stream: &mut BoxedStream, atyp: u8) -> Result<Address, CoreError> {
    match atyp {
        ATYP_V4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            let port = read_port(stream).await?;
            Ok(Address::from((Ipv4Addr::from(octets), port)))
        }
        ATYP_V6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            let port = read_port(stream).await?;
            Ok(Address::from((Ipv6Addr::from(octets), port)))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let len = len[0] as usize;
            if len == 0 {
                return Err(CoreError::Protocol("empty domain".into()));
            }
            let mut host = vec![0u8; len];
            stream.read_exact(&mut host).await?;
            let host = String::from_utf8(host)
                .map_err(|_| CoreError::Protocol("domain is not utf-8".into()))?;
            let port = read_port(stream).await?;
            Ok(parse_host_port(&host, port))
        }
        other => Err(CoreError::Protocol(format!("bad atyp {other:#x}"))),
    }
}

async fn read_port(stream: &mut BoxedStream) -> Result<u16, CoreError> {
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

async fn reply(stream: &mut BoxedStream, rep: u8) -> Result<(), CoreError> {
    // BND.ADDR is a placeholder (0.0.0.0:0); clients ignore it for CONNECT.
    let pkt = [VER, rep, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&pkt).await?;
    stream.flush().await?;
    Ok(())
}

/// Report a successful CONNECT to the client.
pub async fn reply_ok(stream: &mut BoxedStream) -> Result<(), CoreError> {
    reply(stream, REP_SUCCESS).await
}

/// Map an engine error to the closest SOCKS5 reply code and report it.
pub async fn reply_err(stream: &mut BoxedStream, err: &CoreError) -> Result<(), CoreError> {
    let rep = match err {
        CoreError::Blocked => REP_NOT_ALLOWED,
        _ => REP_GENERAL_FAILURE,
    };
    reply(stream, rep).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn boxed(s: tokio::io::DuplexStream) -> BoxedStream {
        Box::pin(s)
    }

    #[tokio::test]
    async fn handshake_domain() {
        let (client, server) = duplex(1024);
        let mut server = boxed(server);
        let mut client = boxed(client);

        let writer = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut sel = [0u8; 2];
            client.read_exact(&mut sel).await.unwrap();
            assert_eq!(sel, [0x05, 0x00]);
            client
                .write_all(&[0x05, 0x01, 0x00, 0x03, 11])
                .await
                .unwrap();
            client.write_all(b"example.com").await.unwrap();
            client.write_all(&443u16.to_be_bytes()).await.unwrap();
        });

        let addr = handshake(&mut server).await.unwrap();
        assert_eq!(addr, Address::Domain("example.com".into(), 443));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_ipv4() {
        let (client, server) = duplex(1024);
        let mut server = boxed(server);
        let mut client = boxed(client);

        let writer = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut sel = [0u8; 2];
            client.read_exact(&mut sel).await.unwrap();
            client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4])
                .await
                .unwrap();
            client.write_all(&80u16.to_be_bytes()).await.unwrap();
        });

        let addr = handshake(&mut server).await.unwrap();
        assert_eq!(
            addr,
            "1.2.3.4:80".parse::<std::net::SocketAddr>().unwrap().into()
        );
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn udp_associate_rejected() {
        let (client, server) = duplex(1024);
        let mut server = boxed(server);
        let mut client = boxed(client);

        let writer = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut sel = [0u8; 2];
            client.read_exact(&mut sel).await.unwrap();
            client
                .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut rep = [0u8; 10];
            client.read_exact(&mut rep).await.unwrap();
            assert_eq!(rep[1], REP_CMD_NOT_SUPPORTED);
        });

        let err = handshake(&mut server).await.unwrap_err();
        assert!(matches!(err, CoreError::Unsupported(_)));
        writer.await.unwrap();
    }
}
