//! Resident Symfony workers — the "service worker" half of esw-engine.
//!
//! Classic FPM pays a full framework bootstrap on every request. A worker boots
//! the kernel once and then handles requests forever, so the steady-state cost
//! is just routing and the controller.
//!
//! Ember owns a pool of worker processes and talks to each over its stdin and
//! stdout pipes — no socket to place, no port to collide, and the pipe closing
//! is an unambiguous signal that the worker died. Frames are:
//!
//! ```text
//! [4 bytes BE header length][4 bytes BE body length][header JSON][body]
//! ```
//!
//! Each worker handles one request at a time; concurrency comes from the pool.

use std::{collections::HashMap, path::PathBuf, process::Stdio, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{Mutex, mpsc},
};

use crate::{config::Config, esw};

/// Requests a worker serves before being replaced.
///
/// A resident PHP process accumulates whatever the application leaks, so
/// recycling is a safety net rather than an optimisation — the same reason FPM
/// has `pm.max_requests`.
const MAX_REQUESTS_PER_WORKER: u32 = 500;

/// How long a single request may occupy a worker.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Serialize)]
struct RequestMeta {
    method: String,
    uri: String,
    headers: HashMap<String, String>,
    cookies: HashMap<String, String>,
    server: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ResponseMeta {
    status: u16,
    #[serde(default)]
    headers: HashMap<String, Vec<String>>,
}

pub struct WorkerResponse {
    pub status: u16,
    pub headers: HashMap<String, Vec<String>>,
    pub body: Vec<u8>,
}

/// One resident PHP process.
struct Worker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    served: u32,
}

impl Worker {
    async fn spawn(cfg: &Config, script: &PathBuf, panel_dir: &PathBuf) -> Result<Self> {
        let php = esw::esw_cli_binary(&cfg.esw_version)?;
        if !php.is_file() {
            bail!(
                "ember's PHP CLI is missing at {} — run `ember esw install`",
                php.display()
            );
        }

        let mut child = Command::new(&php)
            .arg("-d")
            .arg("display_errors=stderr")
            .arg(script)
            .current_dir(panel_dir)
            .env("APP_ENV", "prod")
            .env("APP_DEBUG", "0")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // stderr is the worker's diagnostic channel; it must never be mixed
            // into stdout, which carries the protocol.
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("could not start the worker with {}", php.display()))?;

        let stdin = child.stdin.take().context("worker stdin unavailable")?;
        let stdout = child.stdout.take().context("worker stdout unavailable")?;

        // Relay worker diagnostics into the service log rather than dropping them.
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut lines = tokio::io::BufReader::new(stderr);
                let mut buffer = String::new();
                loop {
                    buffer.clear();
                    use tokio::io::AsyncBufReadExt;
                    match lines.read_line(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let line = buffer.trim_end();
                            if !line.is_empty() {
                                esw::log_line(&format!("worker: {line}"));
                            }
                        }
                    }
                }
            });
        }

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            served: 0,
        })
    }

    /// Send one request and read its response.
    async fn round_trip(&mut self, meta: &RequestMeta, body: &[u8]) -> Result<WorkerResponse> {
        let header = serde_json::to_vec(meta)?;

        self.stdin
            .write_all(&(header.len() as u32).to_be_bytes())
            .await?;
        self.stdin
            .write_all(&(body.len() as u32).to_be_bytes())
            .await?;
        self.stdin.write_all(&header).await?;
        self.stdin.write_all(body).await?;
        self.stdin.flush().await?;

        let mut prefix = [0u8; 8];
        self.stdout
            .read_exact(&mut prefix)
            .await
            .context("worker closed the pipe before responding")?;

        let header_len = u32::from_be_bytes(prefix[0..4].try_into().unwrap()) as usize;
        let body_len = u32::from_be_bytes(prefix[4..8].try_into().unwrap()) as usize;

        let mut header_buf = vec![0u8; header_len];
        self.stdout.read_exact(&mut header_buf).await?;
        let mut body_buf = vec![0u8; body_len];
        self.stdout.read_exact(&mut body_buf).await?;

        let meta: ResponseMeta =
            serde_json::from_slice(&header_buf).context("worker sent a malformed response")?;

        self.served += 1;

        Ok(WorkerResponse {
            status: meta.status,
            headers: meta.headers,
            body: body_buf,
        })
    }

    fn is_spent(&self) -> bool {
        self.served >= MAX_REQUESTS_PER_WORKER
    }

    async fn shutdown(mut self) {
        // Closing stdin ends the worker's read loop, so it exits on its own.
        drop(self.stdin);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
        let _ = self.child.start_kill();
    }
}

/// A fixed set of workers, handed out one request at a time.
pub struct WorkerPool {
    idle: Mutex<mpsc::Receiver<Worker>>,
    ret: mpsc::Sender<Worker>,
    script: PathBuf,
    panel_dir: PathBuf,
    cfg: Config,
    size: usize,
}

impl WorkerPool {
    /// The worker entrypoint a panel must provide to opt into worker mode.
    pub fn script_path(panel_dir: &std::path::Path) -> PathBuf {
        panel_dir.join("bin").join("esw-worker.php")
    }

    /// Build a pool, failing if the very first worker cannot start — a broken
    /// panel should surface at boot, not on the first request.
    pub async fn start(cfg: &Config, panel_dir: PathBuf, size: usize) -> Result<Arc<Self>> {
        let script = Self::script_path(&panel_dir);
        let (ret, idle) = mpsc::channel(size.max(1));

        for index in 0..size {
            let worker = Worker::spawn(cfg, &script, &panel_dir)
                .await
                .with_context(|| format!("could not start worker {}", index + 1))?;
            ret.send(worker)
                .await
                .map_err(|_| anyhow::anyhow!("worker pool closed while starting"))?;
        }

        Ok(Arc::new(Self {
            idle: Mutex::new(idle),
            ret,
            script,
            panel_dir,
            cfg: cfg.clone(),
            size,
        }))
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// Serve one request on the next free worker.
    pub async fn handle(
        &self,
        method: &str,
        uri: &str,
        headers: HashMap<String, String>,
        cookies: HashMap<String, String>,
        server: HashMap<String, String>,
        body: Vec<u8>,
    ) -> Result<WorkerResponse> {
        let mut worker = {
            let mut idle = self.idle.lock().await;
            idle.recv()
                .await
                .context("no workers available; the pool has shut down")?
        };

        let meta = RequestMeta {
            method: method.to_string(),
            uri: uri.to_string(),
            headers,
            cookies,
            server,
        };

        let outcome = tokio::time::timeout(REQUEST_TIMEOUT, worker.round_trip(&meta, &body)).await;

        match outcome {
            Ok(Ok(response)) => {
                // Recycle a spent worker rather than returning it to the pool.
                if worker.is_spent() {
                    self.replace(worker).await;
                } else {
                    let _ = self.ret.send(worker).await;
                }
                Ok(response)
            }
            Ok(Err(err)) => {
                // A protocol error leaves the pipe in an unknown state, so the
                // worker cannot be trusted for another request.
                self.replace(worker).await;
                Err(err)
            }
            Err(_) => {
                self.replace(worker).await;
                bail!(
                    "the panel took longer than {}s to respond",
                    REQUEST_TIMEOUT.as_secs()
                )
            }
        }
    }

    /// Retire a worker and start a fresh one in its place.
    async fn replace(&self, worker: Worker) {
        worker.shutdown().await;
        match Worker::spawn(&self.cfg, &self.script, &self.panel_dir).await {
            Ok(fresh) => {
                let _ = self.ret.send(fresh).await;
            }
            Err(err) => {
                // Losing a worker shrinks the pool but must not take the
                // service down; the remaining workers keep serving.
                esw::log_line(&format!("worker: could not respawn: {err:#}"));
            }
        }
    }

    pub async fn shutdown(&self) {
        let mut idle = self.idle.lock().await;
        idle.close();
        while let Some(worker) = idle.recv().await {
            worker.shutdown().await;
        }
    }
}
