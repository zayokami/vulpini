use std::sync::Mutex;
use tauri::Manager;
use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::CommandEvent;

struct SidecarChild(Mutex<Option<tauri_plugin_shell::process::CommandChild>>);

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let sidecar_cmd = app.shell()
                .sidecar("vulpini")
                .expect("vulpini sidecar not found");

            let (mut rx, child) = sidecar_cmd
                .spawn()
                .expect("failed to spawn vulpini sidecar");

            app.manage(SidecarChild(Mutex::new(Some(child))));

            // Log sidecar output in a background task.
            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stdout(line) => {
                            print!("[vulpini] {}", String::from_utf8_lossy(&line));
                        }
                        CommandEvent::Stderr(line) => {
                            eprint!("[vulpini] {}", String::from_utf8_lossy(&line));
                        }
                        CommandEvent::Terminated(status) => {
                            eprintln!("[vulpini] process terminated: {:?}", status);
                            break;
                        }
                        _ => {}
                    }
                }
            });

            // Kill sidecar when the main window is closed.
            let window = app.get_webview_window("main")
                .expect("main window not found");
            let app_handle = app.handle().clone();
            window.on_window_event(move |event| {
                if let tauri::WindowEvent::CloseRequested { .. } = event {
                    let state = app_handle.state::<SidecarChild>();
                    // Take the child out while holding the lock, then drop
                    // the guard before `state` itself goes out of scope.
                    let child = state.0.lock().unwrap().take();
                    if let Some(child) = child {
                        let _ = child.kill();
                    }
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
