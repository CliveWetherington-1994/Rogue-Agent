//! Native Windows window for Rogue Agent.
//!
//! Starts the bundled Node.js runtime with the desktop server, waits for its
//! one-line ready report, and shows the UI in a WebView2 window. The engine
//! process lives in a kill-on-close Job Object, so closing the window — or a
//! crash of this process — always stops Node and the Ghidra JVM it started.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("RogueAgent.exe is the Windows window. On other systems run `npm run desktop`.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    if let Err(message) = app::run() {
        app::fatal(&message);
    }
}

#[cfg(windows)]
mod app {
    use std::fs::{self, File, OpenOptions};
    use std::io::{BufRead, BufReader, Write};
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use serde::Deserialize;
    use tao::dpi::LogicalSize;
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
    use tao::platform::windows::IconExtWindows;
    use tao::window::{Icon, WindowBuilder};
    use wry::{DragDropEvent, NewWindowResponse, WebContext, WebViewBuilder};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const READY_PREFIX: &str = "ROGUE_AGENT_READY ";
    const READY_TIMEOUT: Duration = Duration::from_secs(90);
    const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

    #[derive(Deserialize)]
    struct Ready {
        url: String,
        port: u16,
    }

    #[derive(Deserialize)]
    #[serde(tag = "type")]
    enum IpcMessage {
        #[serde(rename = "pick")]
        Pick {
            mode: String,
            #[serde(rename = "requestId")]
            request_id: u64,
            suggested: Option<String>,
        },
        /// The UI connected to the engine and rendered its first state.
        #[serde(rename = "loaded")]
        Loaded { version: String },
    }

    enum UserEvent {
        Script(String),
        Loaded(String),
        EngineExited,
    }

    struct Layout {
        node: PathBuf,
        entry: PathBuf,
        install_dir: PathBuf,
    }

    /// Installed layout: RogueAgent.exe, runtime\node.exe, app\scripts\…
    /// Development layout: ROGUE_AGENT_APP_DIR points at a repository checkout
    /// and `node` comes from PATH.
    fn layout() -> Result<Layout, String> {
        let exe = std::env::current_exe().map_err(|e| format!("Cannot locate RogueAgent.exe: {e}"))?;
        let install_dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
        let node = install_dir.join("runtime").join("node.exe");
        let entry = install_dir.join("app").join("scripts").join("rogue-agent-desktop.mjs");
        if node.is_file() && entry.is_file() {
            return Ok(Layout { node, entry, install_dir });
        }
        if let Some(app_dir) = std::env::var_os("ROGUE_AGENT_APP_DIR") {
            let entry = PathBuf::from(app_dir).join("scripts").join("rogue-agent-desktop.mjs");
            if entry.is_file() {
                return Ok(Layout { node: PathBuf::from("node.exe"), entry, install_dir });
            }
        }
        Err(format!(
            "Rogue Agent is incomplete: expected {} and {}. Reinstall the application.",
            node.display(),
            entry.display()
        ))
    }

    fn data_dir() -> PathBuf {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join("RogueAgent");
        let _ = fs::create_dir_all(dir.join("logs"));
        dir
    }

    fn log_line(log: &Mutex<File>, message: &str) {
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        if let Ok(mut file) = log.lock() {
            let _ = writeln!(file, "[{seconds}] {message}");
        }
    }

    pub fn fatal(message: &str) {
        rfd::MessageDialog::new()
            .set_level(rfd::MessageLevel::Error)
            .set_title("Rogue Agent")
            .set_description(message)
            .set_buttons(rfd::MessageButtons::Ok)
            .show();
        std::process::exit(1);
    }

    /// Kill-on-close Job Object holding the engine process tree.
    mod job {
        use std::os::windows::io::AsRawHandle;
        use std::process::Child;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        /// Closing the handle (drop, or this process exiting) kills whatever
        /// is still running in the job, including an orphaned Ghidra JVM.
        pub struct Job(HANDLE);
        // The handle is owned by one Engine and never shared between threads.
        unsafe impl Send for Job {}

        impl Drop for Job {
            fn drop(&mut self) {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }

        pub fn contain(child: &Child) -> Option<Job> {
            unsafe {
                let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if job.is_null() {
                    return None;
                }
                let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let applied = SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &limits as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                if applied == 0 || AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) == 0 {
                    return None;
                }
                Some(Job(job))
            }
        }
    }

    struct Engine {
        child: Arc<Mutex<Child>>,
        stdin: Option<ChildStdin>,
        _job: Option<job::Job>,
    }

    impl Engine {
        /// Close stdin so the server shuts Ghidra down, then force-stop it.
        fn stop(&mut self) {
            drop(self.stdin.take());
            let deadline = Instant::now() + SHUTDOWN_GRACE;
            while Instant::now() < deadline {
                if let Ok(mut child) = self.child.lock() {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        return;
                    }
                }
                thread::sleep(Duration::from_millis(50));
            }
            if let Ok(mut child) = self.child.lock() {
                let _ = child.kill();
            }
        }
    }

    fn start_engine(
        layout: &Layout,
        data: &Path,
        open_file: Option<&Path>,
        log: Arc<Mutex<File>>,
    ) -> Result<(Engine, mpsc::Receiver<Result<Ready, String>>, mpsc::Receiver<()>), String> {
        let engine_log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(data.join("logs").join("engine.log"))
            .map_err(|e| format!("Cannot write the engine log: {e}"))?;
        let mut command = Command::new(&layout.node);
        command
            .arg(&layout.entry)
            .arg("--exit-with-stdin")
            .arg("--app-dir")
            .arg(&layout.install_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(engine_log))
            .creation_flags(CREATE_NO_WINDOW);
        if let Some(path) = open_file {
            command.arg("--open").arg(path);
        }
        let mut child = command.spawn().map_err(|e| {
            format!("Cannot start the analysis engine ({}): {e}", layout.node.display())
        })?;
        let job = job::contain(&child);
        if job.is_none() {
            log_line(&log, "warning: engine is not contained in a Job Object");
        }
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().ok_or("Engine stdout is unavailable")?;
        let (ready_tx, ready_rx) = mpsc::channel();
        let (exit_tx, exit_rx) = mpsc::channel();
        let reader_log = Arc::clone(&log);
        thread::spawn(move || {
            let mut announced = false;
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if !announced {
                    if let Some(json) = line.strip_prefix(READY_PREFIX) {
                        announced = true;
                        let _ = ready_tx.send(
                            serde_json::from_str::<Ready>(json).map_err(|e| format!("Bad ready report: {e}")),
                        );
                        continue;
                    }
                }
                log_line(&reader_log, &format!("engine: {line}"));
            }
            if !announced {
                let _ = ready_tx.send(Err("The analysis engine exited during startup.".into()));
            }
            let _ = exit_tx.send(());
        });
        Ok((
            Engine { child: Arc::new(Mutex::new(child)), stdin, _job: job },
            ready_rx,
            exit_rx,
        ))
    }

    fn quote_js(value: &str) -> String {
        serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into())
    }

    fn handle_ipc(body: &str, proxy: &EventLoopProxy<UserEvent>) {
        let (mode, request_id, suggested) = match serde_json::from_str(body) {
            Ok(IpcMessage::Pick { mode, request_id, suggested }) => (mode, request_id, suggested),
            Ok(IpcMessage::Loaded { version }) => {
                let _ = proxy.send_event(UserEvent::Loaded(version));
                return;
            }
            Err(_) => return,
        };
        let mut dialog = rfd::FileDialog::new();
        let picked = if mode == "save" {
            dialog = dialog.add_filter("C source", &["c"]).set_title("Export decompiled C");
            if let Some(suggested) = suggested.as_deref().map(Path::new) {
                if let Some(parent) = suggested.parent() {
                    dialog = dialog.set_directory(parent);
                }
                if let Some(name) = suggested.file_name() {
                    dialog = dialog.set_file_name(name.to_string_lossy());
                }
            }
            dialog.save_file()
        } else {
            dialog
                .set_title("Open a binary")
                .add_filter("Programs and libraries", &["exe", "dll", "sys", "ocx", "cpl", "scr", "efi", "so", "elf", "bin", "o", "dylib"])
                .add_filter("All files", &["*"])
                .pick_file()
        };
        let path = picked.map(|p| p.to_string_lossy().into_owned());
        let reply = serde_json::json!({ "requestId": request_id, "path": path });
        let _ = proxy.send_event(UserEvent::Script(format!("window.__rogueIpcReply({reply})")));
    }

    pub fn run() -> Result<(), String> {
        let data = data_dir();
        let log = Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(data.join("logs").join("launcher.log"))
                .map_err(|e| format!("Cannot write the launcher log: {e}"))?,
        ));
        let layout = layout()?;
        let arguments: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
        // `--smoke-test <marker>`: prove the window, WebView2 and engine work,
        // write the marker and exit (used by CI on a real Windows host).
        let smoke_marker = arguments
            .iter()
            .position(|argument| argument == "--smoke-test")
            .map(|index| arguments.get(index + 1).map(PathBuf::from).unwrap_or_else(|| data.join("smoke.txt")));
        let open_file = arguments.first().map(PathBuf::from).filter(|p| p.is_file());
        log_line(&log, &format!("starting engine {}", layout.entry.display()));
        let (mut engine, ready_rx, exit_rx) = start_engine(&layout, &data, open_file.as_deref(), Arc::clone(&log))?;
        let ready = match ready_rx.recv_timeout(READY_TIMEOUT) {
            Ok(Ok(ready)) => ready,
            Ok(Err(message)) => {
                engine.stop();
                return Err(format!("{message}\n\nDetails: {}", data.join("logs").join("engine.log").display()));
            }
            Err(_) => {
                engine.stop();
                return Err("The analysis engine did not start in time.".into());
            }
        };
        log_line(&log, &format!("engine ready on port {}", ready.port));

        let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
        let proxy = event_loop.create_proxy();
        let exit_proxy = event_loop.create_proxy();
        thread::spawn(move || {
            if exit_rx.recv().is_ok() {
                let _ = exit_proxy.send_event(UserEvent::EngineExited);
            }
        });

        let icon = Icon::from_resource(1, None).ok();
        let window = WindowBuilder::new()
            .with_title("Rogue Agent")
            .with_inner_size(LogicalSize::new(1360.0, 860.0))
            .with_min_inner_size(LogicalSize::new(820.0, 520.0))
            .with_window_icon(icon)
            .build(&event_loop)
            .map_err(|e| format!("Cannot create the window: {e}"))?;

        let origin = format!("http://127.0.0.1:{}/", ready.port);
        let mut context = WebContext::new(Some(data.join("WebView2")));
        let ipc_proxy = proxy.clone();
        let drop_proxy = proxy.clone();
        let navigation_origin = origin.clone();
        let webview = WebViewBuilder::new_with_web_context(&mut context)
            .with_url(&ready.url)
            .with_devtools(cfg!(debug_assertions))
            .with_ipc_handler(move |request| handle_ipc(request.body(), &ipc_proxy))
            .with_drag_drop_handler(move |event| {
                if let DragDropEvent::Drop { paths, .. } = event {
                    if let Some(path) = paths.into_iter().find(|p| p.is_file()) {
                        let script = format!("window.__rogueOpenPath({})", quote_js(&path.to_string_lossy()));
                        let _ = drop_proxy.send_event(UserEvent::Script(script));
                    }
                }
                true
            })
            .with_navigation_handler(move |url| {
                if url.starts_with(&navigation_origin) {
                    return true;
                }
                if url.starts_with("https://") {
                    let _ = open::that_detached(&url);
                }
                false
            })
            .with_new_window_req_handler(|url, _features| {
                if url.starts_with("https://") {
                    let _ = open::that_detached(&url);
                }
                NewWindowResponse::Deny
            })
            .build(&window);
        let webview = match webview {
            Ok(webview) => webview,
            Err(error) => {
                log_line(&log, &format!("webview unavailable: {error}"));
                let open_browser = rfd::MessageDialog::new()
                    .set_level(rfd::MessageLevel::Warning)
                    .set_title("Rogue Agent")
                    .set_description(
                        "The Microsoft Edge WebView2 Runtime is not available, so Rogue Agent cannot draw its window.\n\n\
                         Open Rogue Agent in your web browser instead? (Install WebView2 from https://developer.microsoft.com/microsoft-edge/webview2/ for the native window.)",
                    )
                    .set_buttons(rfd::MessageButtons::YesNo)
                    .show();
                if open_browser == rfd::MessageDialogResult::Yes {
                    let _ = open::that_detached(&ready.url);
                    rfd::MessageDialog::new()
                        .set_title("Rogue Agent")
                        .set_description("Rogue Agent is running in your browser. Click OK to quit.")
                        .set_buttons(rfd::MessageButtons::Ok)
                        .show();
                }
                engine.stop();
                return Ok(());
            }
        };

        let mut engine = Some(engine);
        event_loop.run(move |event, _, control_flow| {
            *control_flow = ControlFlow::Wait;
            match event {
                Event::UserEvent(UserEvent::Script(script)) => {
                    let _ = webview.evaluate_script(&script);
                }
                Event::UserEvent(UserEvent::Loaded(version)) => {
                    log_line(&log, &format!("ui loaded, engine v{version}"));
                    if let Some(marker) = smoke_marker.as_ref() {
                        let _ = fs::write(marker, format!("SMOKE_OK {version} port {}\n", ready.port));
                        if let Some(mut running) = engine.take() {
                            running.stop();
                        }
                        *control_flow = ControlFlow::Exit;
                    }
                }
                Event::UserEvent(UserEvent::EngineExited) => {
                    log_line(&log, "engine exited");
                    if engine.is_some() {
                        rfd::MessageDialog::new()
                            .set_level(rfd::MessageLevel::Error)
                            .set_title("Rogue Agent")
                            .set_description(format!(
                                "The analysis engine stopped unexpectedly.\n\nDetails: {}",
                                data.join("logs").join("engine.log").display()
                            ))
                            .show();
                    }
                    engine = None;
                    *control_flow = ControlFlow::Exit;
                }
                Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                    window.set_visible(false);
                    if let Some(mut running) = engine.take() {
                        running.stop();
                    }
                    *control_flow = ControlFlow::Exit;
                }
                _ => {}
            }
        });
    }
}
