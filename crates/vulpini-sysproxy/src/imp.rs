//! Windows implementation: HKCU Internet Settings + WinINet refresh.

use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

use super::{SysProxyError, SysProxyStatus};

const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

fn open_key() -> Result<RegKey, SysProxyError> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(SUBKEY, winreg::enums::KEY_READ | winreg::enums::KEY_WRITE)
        .map_err(|e| SysProxyError::Registry(e.to_string()))
}

pub fn status() -> Result<SysProxyStatus, SysProxyError> {
    let key = open_key()?;
    let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
    let server: Option<String> = key.get_value("ProxyServer").ok();
    Ok(SysProxyStatus {
        enabled: enabled != 0,
        server,
    })
}

pub fn enable(server: &str, bypass: &str) -> Result<SysProxyStatus, SysProxyError> {
    let previous = status()?;
    let key = open_key()?;
    key.set_value("ProxyServer", &server)
        .map_err(|e| SysProxyError::Registry(e.to_string()))?;
    key.set_value("ProxyOverride", &bypass.to_string())
        .map_err(|e| SysProxyError::Registry(e.to_string()))?;
    key.set_value("ProxyEnable", &1u32)
        .map_err(|e| SysProxyError::Registry(e.to_string()))?;
    notify_change();
    Ok(previous)
}

pub fn disable(previous: &SysProxyStatus) -> Result<(), SysProxyError> {
    let key = open_key()?;
    key.set_value("ProxyEnable", &(previous.enabled as u32))
        .map_err(|e| SysProxyError::Registry(e.to_string()))?;
    match &previous.server {
        Some(server) => key
            .set_value("ProxyServer", server)
            .map_err(|e| SysProxyError::Registry(e.to_string()))?,
        None => {
            // Value did not exist before us; delete it back.
            let _ = key.delete_value("ProxyServer");
        }
    }
    notify_change();
    Ok(())
}

/// Tell running apps the settings changed (no relogin needed).
fn notify_change() {
    use windows_sys::Win32::Networking::WinInet::{
        INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
    };
    unsafe {
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        );
    }
}
