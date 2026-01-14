use anyhow::{Result, Context};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::HttpProxyConfig;

pub struct HttpProtocol {
    _config: HttpProxyConfig,
}

impl HttpProtocol {
    pub fn new(config: HttpProxyConfig) -> Self {
        Self { _config: config }
    }

    pub async fn start(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr)
            .await
            .context(format!("Failed to bind to {}", addr))?;
        
        println!("HTTP proxy server listening on {}", addr);
        
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
        let mut buf = [0u8; 8192];
        
        loop {
            match socket.read(&mut buf).await {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    let request_str = String::from_utf8_lossy(&buf[..n]);
                    
                    if request_str.starts_with("CONNECT ") {
                        if let Some(host_port) = request_str.trim_start_matches("CONNECT ").split_whitespace().next() {
                            let parts: Vec<&str> = host_port.split(':').collect();
                            let host = parts[0];
                            let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);
                            
                            match TcpStream::connect(format!("{}:{}", host, port)).await {
                                Ok(mut upstream) => {
                                    socket.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                                    
                                    tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;
                                }
                                Err(e) => {
                                    socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                                    println!("Failed to connect to {}:{}: {}", host, port, e);
                                }
                            }
                        } else {
                            socket.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
                        }
                    } else {
                        socket.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await?;
                    }
                }
                Err(e) => {
                    println!("Read error: {}", e);
                    return Err(e.into());
                }
            }
        }
    }
}
