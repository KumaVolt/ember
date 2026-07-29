//! Background work, queued and visible.
//!
//! Installing a package takes minutes. Doing it inside the request meant a form
//! that hung with no indication whether it was working, waiting on someone
//! else's lock, or dead — and two at once collided on dpkg.
//!
//! So work is queued instead. One worker runs one job at a time, which *is* the
//! serialisation: there is no separate lock to get wrong. Before running
//! anything that touches packages the queue checks whether the dpkg lock is
//! already held elsewhere, and says who has it rather than blocking silently.

use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex, OnceLock},
};

use serde::Serialize;

use crate::config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Accepted, behind other work.
    Queued,
    /// Ready to run, but something outside Ember holds the package lock.
    Waiting,
    Running,
    Done,
    Failed,
}

/// What a job actually does.
#[derive(Debug, Clone)]
pub enum Work {
    InstallService(String),
    InstallNode(String),
}

impl Work {
    fn label(&self) -> String {
        match self {
            Self::InstallService(id) => format!("Install {id}"),
            Self::InstallNode(major) => format!("Install Node {major}"),
        }
    }

    /// Whether this job needs the package manager, and so the lock check.
    fn uses_packages(&self) -> bool {
        true
    }

    fn run(&self, cfg: &Config) -> anyhow::Result<String> {
        match self {
            Self::InstallService(id) => crate::services::install(cfg, id),
            Self::InstallNode(major) => crate::services::install_node(cfg, major),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Job {
    pub id: u64,
    pub label: String,
    pub status: Status,
    /// What happened, or what it is waiting for.
    pub message: String,
    pub queued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<u64>,
}

struct Queue {
    /// Everything, in order. Kept short by trimming finished jobs.
    jobs: Mutex<Vec<Job>>,
    pending: Mutex<VecDeque<(u64, Work)>>,
    wake: Condvar,
    next_id: Mutex<u64>,
}

static QUEUE: OnceLock<Arc<Queue>> = OnceLock::new();

/// How many finished jobs to keep for display.
const HISTORY: usize = 20;

fn queue(cfg: &Config) -> Arc<Queue> {
    QUEUE
        .get_or_init(|| {
            let queue = Arc::new(Queue {
                jobs: Mutex::new(Vec::new()),
                pending: Mutex::new(VecDeque::new()),
                wake: Condvar::new(),
                next_id: Mutex::new(1),
            });

            // One worker, so jobs are serialised by construction rather than by
            // a lock someone has to remember to take.
            let worker = Arc::clone(&queue);
            let cfg = cfg.clone();
            std::thread::Builder::new()
                .name("ember-jobs".into())
                .spawn(move || worker_loop(worker, cfg))
                .ok();

            queue
        })
        .clone()
}

fn worker_loop(queue: Arc<Queue>, cfg: Config) {
    loop {
        let (id, work) = {
            let mut pending = queue.pending.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if let Some(next) = pending.pop_front() {
                    break next;
                }
                pending = queue.wake.wait(pending).unwrap_or_else(|e| e.into_inner());
            }
        };

        // Say what is happening before blocking on it. A job that sits for two
        // minutes because unattended-upgrades holds the lock should say so.
        if work.uses_packages()
            && let Some(holder) = package_lock_holder()
        {
            set_status(
                &queue,
                id,
                Status::Waiting,
                format!("waiting for {holder} to finish with the package manager"),
            );
        }

        set_status(&queue, id, Status::Running, "running".into());

        let outcome = work.run(&cfg);
        let now = crate::daemon::now_secs();

        let mut jobs = queue.jobs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(job) = jobs.iter_mut().find(|job| job.id == id) {
            match outcome {
                Ok(message) => {
                    job.status = Status::Done;
                    job.message = message;
                }
                Err(err) => {
                    job.status = Status::Failed;
                    job.message = format!("{err:#}");
                }
            }
            job.finished_at = Some(now);
            crate::esw::log_line(&format!("[{now}] job {id}: {}", job.message));
        }

        // Keep the list readable; unfinished jobs are never trimmed.
        let finished: Vec<u64> = jobs
            .iter()
            .filter(|job| job.finished_at.is_some())
            .map(|job| job.id)
            .collect();
        if finished.len() > HISTORY {
            let drop_before = finished[finished.len() - HISTORY];
            jobs.retain(|job| job.finished_at.is_none() || job.id >= drop_before);
        }
    }
}

fn set_status(queue: &Arc<Queue>, id: u64, status: Status, message: String) {
    let mut jobs = queue.jobs.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(job) = jobs.iter_mut().find(|job| job.id == id) {
        job.status = status;
        job.message = message;
    }
}

/// Add work to the queue. Returns immediately with the job.
pub fn submit(cfg: &Config, work: Work) -> Job {
    let queue = queue(cfg);

    let id = {
        let mut next = queue.next_id.lock().unwrap_or_else(|e| e.into_inner());
        let id = *next;
        *next += 1;
        id
    };

    let ahead = queue
        .pending
        .lock()
        .map(|pending| pending.len())
        .unwrap_or(0);

    let job = Job {
        id,
        label: work.label(),
        status: Status::Queued,
        message: if ahead == 0 {
            "queued".into()
        } else {
            format!("queued behind {ahead} other job(s)")
        },
        queued_at: crate::daemon::now_secs(),
        finished_at: None,
    };

    queue
        .jobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(job.clone());

    queue
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push_back((id, work));
    queue.wake.notify_one();

    job
}

/// Everything the queue knows about, newest first.
pub fn list(cfg: &Config) -> Vec<Job> {
    let queue = queue(cfg);
    let jobs = queue.jobs.lock().unwrap_or_else(|e| e.into_inner());
    let mut all = jobs.clone();
    all.reverse();
    all
}

/// Is anything still in flight? Lets the UI know whether to keep refreshing.
pub fn busy(cfg: &Config) -> bool {
    list(cfg).iter().any(|job| {
        matches!(
            job.status,
            Status::Queued | Status::Waiting | Status::Running
        )
    })
}

// ---------------------------------------------------------------------------
// The package lock
// ---------------------------------------------------------------------------

/// Who is holding dpkg's lock, if anyone.
///
/// Checked rather than assumed: "waiting for unattended-upgrades" is an answer
/// an operator can act on — wait — where a silent stall is not.
pub fn package_lock_holder() -> Option<String> {
    let lock = "/var/lib/dpkg/lock-frontend";
    if !std::path::Path::new(lock).exists() {
        return None;
    }

    // fuser prints the pids holding the file. It is in psmisc, which is not
    // always installed, so a process scan backs it up.
    if let Ok(output) = std::process::Command::new("fuser").arg(lock).output()
        && output.status.success()
    {
        if let Some(pid) = String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .next()
            .and_then(|pid| pid.trim().parse::<u32>().ok())
        {
            return Some(process_name(pid).unwrap_or_else(|| format!("process {pid}")));
        }
        return None;
    }

    for name in ["unattended-upgr", "apt-get", "apt", "dpkg", "aptitude"] {
        if std::process::Command::new("pgrep")
            .args(["-x", name])
            .stdout(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
        {
            return Some(name.to_string());
        }
    }

    None
}

fn process_name(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
}
