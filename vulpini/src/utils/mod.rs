use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

pub fn parse_address(addr: &str) -> Option<SocketAddr> {
    if let Ok(addr) = addr.parse() {
        return Some(addr);
    }
    
    if let Some((host, port)) = addr.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            let addr_tuple = (host, port);
            if let Ok(sock_addrs) = addr_tuple.to_socket_addrs() {
                for sock_addr in sock_addrs {
                    return Some(sock_addr);
                }
            }
        }
    }
    
    None
}

pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    let secs_f = secs as f64 + millis as f64 / 1000.0;
    
    if secs >= 3600 {
        let hours = secs / 3600;
        let minutes = (secs % 3600) / 60;
        format!("{}h {}m {:.1}s", hours, minutes, secs_f % 60.0)
    } else if secs >= 60 {
        let minutes = secs / 60;
        format!("{}m {:.1}s", minutes, secs_f % 60.0)
    } else {
        format!("{:.1}s", secs_f)
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

pub fn generate_session_id() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const LENGTH: usize = 32;

    let session_id: String = (0..LENGTH)
        .map(|_| {
            let idx = rand::random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    
    session_id
}
