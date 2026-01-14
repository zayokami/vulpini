use anyhow::{Result, Context};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::Socks5Config;

const SOCKS5_VERSION: u8 = 0x05;

pub struct Socks5Protocol {
    _config: Socks5Config,
}

impl Socks5Protocol {
    pub fn new(config: Socks5Config) -> Self {
        Self { _config: config }
    }

    pub async fn start(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr)
            .await
            .context(format!("Failed to bind to {}", addr))?;
        
        println!("SOCKS5 server listening on {}", addr);
        
        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    println!("Accepted connection from {}", peer_addr);
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(socket).await {
                            println!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    println!("Accept error: {}", e);
                }
            }
        }
    }

    async fn handle_connection(
        mut socket: TcpStream,
    ) -> Result<()> {
        let mut buf = [0u8; 262];
        
        let n = socket.read(&mut buf).await.context("Failed to read greeting")?;
        if n < 3 {
            return Ok(());
        }
        
        if buf[0] != SOCKS5_VERSION {
            return Ok(());
        }
        
        socket.write_all(&[SOCKS5_VERSION, 0x00]).await?;
        
        let n = socket.read(&mut buf).await.context("Failed to read request")?;
        if n < 4 {
            return Ok(());
        }
        
        let atyp = buf[3];
        
        let target_port = u16::from_be_bytes([buf[8], buf[9]]);
        
        if atyp == 0x01 {
            if n < 10 {
                return Ok(());
            }
            let target_addr = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            
            let mut upstream = TcpStream::connect(format!("{}:{}", target_addr, target_port))
                .await
                .context(format!("Failed to connect to {}:{}", target_addr, target_port))?;
            
            socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00]).await?;
            
            tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;
        } else if atyp == 0x03 {
            if n < 5 {
                return Ok(());
            }
            let domain_len = buf[4] as usize;
            if n < 5 + domain_len + 2 {
                return Ok(());
            }
            let target_addr = String::from_utf8_lossy(&buf[5..5 + domain_len]).to_string();
            
            let mut upstream = TcpStream::connect(format!("{}:{}", target_addr, target_port))
                .await
                .context(format!("Failed to connect to {}:{}", target_addr, target_port))?;
            
            socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00]).await?;
            
            tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;
        }
        
        Ok(())
    }
}
