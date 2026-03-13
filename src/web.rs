use crate::fuzz::WebCommand;
use crate::Strategy;
use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    fmt::Write as FmtWrite,
    io::Write,
    net::{Shutdown, TcpListener},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

/// Validate log file name: afl, afl_N, honggfuzz, or libfuzzer.
fn is_valid_log_name(name: &str) -> bool {
    match name {
        "afl" | "honggfuzz" | "libfuzzer" => true,
        _ => {
            if let Some(suffix) = name.strip_prefix("afl_") {
                !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
            } else {
                false
            }
        }
    }
}

/// Render a standalone log viewer HTML page.
fn render_log_page(name: &str, content: &str) -> String {
    let escaped = content
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let mut buf = String::with_capacity(content.len() + 512);
    let _ = write!(
        buf,
        r#"<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="1">
<title>multifuzz — logs: {name}.log</title>
<style>
body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; margin: 0; }}
h1 {{ color: #00d4ff; font-size: 1.2em; }}
a {{ color: #00d4ff; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
pre {{ white-space: pre-wrap; word-wrap: break-word; }}
</style>
</head><body>
<h1>multifuzz &mdash; logs: {name}.log &nbsp; <a href="/">&larr; Back</a></h1>
<pre>{escaped}</pre>
<script>window.scrollTo(0,document.body.scrollHeight)</script>
</body></html>"#
    );
    buf
}

pub fn start_server(
    port: u16,
    html: Arc<Mutex<HashMap<String, String>>>,
    cmd_tx: mpsc::Sender<WebCommand>,
    stop: &'static AtomicBool,
    logs_dir: String,
) -> Result<(JoinHandle<()>, u16)> {
    // Try up to 100 ports on conflict.
    let (listener, bound_port) = {
        let mut last_err = None;
        let mut found = None;
        for p in port..port + 100 {
            match TcpListener::bind(("127.0.0.1", p)) {
                Ok(l) => {
                    found = Some((l, p));
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        found.ok_or_else(|| {
            anyhow::anyhow!(
                "Could not bind to ports {}-{}: {}",
                port,
                port + 99,
                last_err.unwrap()
            )
        })?
    };

    listener
        .set_nonblocking(true)
        .context("Failed to set non-blocking on TcpListener")?;

    let handle = thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                    let mut req_buf = [0u8; 4096];
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                    let n = match std::io::Read::read(&mut stream, &mut req_buf) {
                        Ok(n) => n,
                        Err(_) => continue,
                    };
                    let req = String::from_utf8_lossy(&req_buf[..n]);
                    let first_line = req.lines().next().unwrap_or("");
                    // Parse: GET /path?query HTTP/1.1
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    if parts.len() < 2 {
                        continue;
                    }
                    let full_path = parts[1];

                    let (path, query) = match full_path.split_once('?') {
                        Some((p, q)) => (p, q),
                        None => (full_path, ""),
                    };

                    match path {
                        "/" => {
                            let tab = query
                                .split('&')
                                .find_map(|kv| {
                                    let (k, v) = kv.split_once('=')?;
                                    if k == "tab" {
                                        Some(v)
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or("exec");
                            let tab = match tab {
                                "exec" | "corpus" | "cpu" | "mem" => tab,
                                _ => "exec",
                            };
                            let guard = html.lock().unwrap();
                            let body = guard.get(tab).cloned().unwrap_or_default();
                            drop(guard);
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = stream.write_all(resp.as_bytes());
                        }
                        "/logs" => {
                            let name = query.split('&').find_map(|kv| {
                                let (k, v) = kv.split_once('=')?;
                                if k == "f" {
                                    Some(v)
                                } else {
                                    None
                                }
                            });
                            if let Some(name) = name.filter(|n| is_valid_log_name(n)) {
                                let log_path = format!("{}/{name}.log", logs_dir);
                                let raw = crate::ui::tail_file(&log_path, 32768);
                                let content = crate::ui::strip_ansi_inline(&raw);
                                let body = render_log_page(name, &content);
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                );
                                let _ = stream.write_all(resp.as_bytes());
                            } else {
                                let resp =
                                    "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nNot Found";
                                let _ = stream.write_all(resp.as_bytes());
                            }
                        }
                        "/switch" => {
                            // Parse ?s=strategy
                            let strategy = query.split('&').find_map(|kv| {
                                let (k, v) = kv.split_once('=')?;
                                if k == "s" {
                                    Some(v)
                                } else {
                                    None
                                }
                            });
                            if let Some(s) = strategy {
                                let strat = match s {
                                    "parallel" => Some(Strategy::Parallel),
                                    "afl-only" => Some(Strategy::AflOnly),
                                    "hongg-only" => Some(Strategy::HonggOnly),
                                    "libfuzzer-only" => Some(Strategy::LibfuzzerOnly),
                                    _ => None,
                                };
                                if let Some(st) = strat {
                                    let _ = cmd_tx.send(WebCommand::SwitchStrategy(st));
                                }
                            }
                            let resp = "HTTP/1.1 303 See Other\r\nLocation: /\r\nConnection: close\r\n\r\n";
                            let _ = stream.write_all(resp.as_bytes());
                        }
                        "/scale" => {
                            // Parse ?e=afl&d=N
                            let mut engine = None;
                            let mut delta = None;
                            for kv in query.split('&') {
                                if let Some((k, v)) = kv.split_once('=') {
                                    match k {
                                        "e" => engine = Some(v),
                                        "d" => delta = v.parse::<i32>().ok(),
                                        _ => {}
                                    }
                                }
                            }
                            if engine == Some("afl") {
                                if let Some(d) = delta {
                                    let _ = cmd_tx.send(WebCommand::ScaleAfl(d));
                                }
                            }
                            let resp = "HTTP/1.1 303 See Other\r\nLocation: /\r\nConnection: close\r\n\r\n";
                            let _ = stream.write_all(resp.as_bytes());
                        }
                        "/pause" | "/resume" | "/remove" => {
                            let slot = query.split('&').find_map(|kv| {
                                let (k, v) = kv.split_once('=')?;
                                if k == "slot" {
                                    v.parse::<usize>().ok()
                                } else {
                                    None
                                }
                            });
                            if let Some(s) = slot {
                                let cmd = match path {
                                    "/pause" => WebCommand::PauseSlot(s),
                                    "/resume" => WebCommand::ResumeSlot(s),
                                    "/remove" => WebCommand::RemoveSlot(s),
                                    _ => unreachable!(),
                                };
                                let _ = cmd_tx.send(cmd);
                            }
                            let resp = "HTTP/1.1 303 See Other\r\nLocation: /\r\nConnection: close\r\n\r\n";
                            let _ = stream.write_all(resp.as_bytes());
                        }
                        "/stop" => {
                            stop.store(true, Ordering::Relaxed);
                            let resp = "HTTP/1.1 303 See Other\r\nLocation: /\r\nConnection: close\r\n\r\n";
                            let _ = stream.write_all(resp.as_bytes());
                        }
                        _ => {
                            let resp =
                                "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nNot Found";
                            let _ = stream.write_all(resp.as_bytes());
                        }
                    }
                    // Graceful close: shutdown write side so the kernel sends FIN
                    // instead of RST if any request bytes remain unread.
                    let _ = stream.shutdown(Shutdown::Write);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(200));
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(200));
                }
            }
        }
    });

    Ok((handle, bound_port))
}
