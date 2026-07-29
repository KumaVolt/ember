//! The HTTP edge.
//!
//! Ember is the web server: it terminates HTTP itself and speaks FastCGI to the
//! esw-engine pool it supervises — the same role nginx would play, minus nginx.
//! Static files under the panel's `public/` are served directly; everything
//! else goes to the Symfony front controller.

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Router,
    body::Body,
    extract::{FromRequest, Request, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use fastcgi_client::{Client, Params, Request as FcgiRequest};

use crate::{
    accounts::{self, Source},
    auth, cert,
    config::{self, Config},
    daemon::{self, State as ServiceState},
    database,
    esw::{self, EswProcess, PoolAddr},
    files, jobs, pages, php, secrets, services, store, system, vhost,
    worker::WorkerPool,
};

/// Request bodies larger than this are rejected rather than buffered.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
struct AppState(Arc<Inner>);

struct Inner {
    public_dir: PathBuf,
    pool: PoolAddr,
    host: String,
    port: u16,
    esw_version: String,
    mode: config::Mode,
    started_at: u64,
    /// Present when the panel provides a worker entrypoint. Requests then skip
    /// FastCGI entirely and go to a resident Symfony process.
    workers: Option<Arc<WorkerPool>>,
    /// Failed sign-in attempts, keyed by username. Brute force is the obvious
    /// attack on a password form, so it is throttled from the start.
    throttle: std::sync::Mutex<HashMap<String, Attempts>>,
}

#[derive(Debug, Clone, Copy)]
struct Attempts {
    count: u32,
    locked_until: u64,
}

/// Failures tolerated before an account is briefly locked out.
const MAX_ATTEMPTS: u32 = 5;
/// How long a lockout lasts.
const LOCKOUT_SECS: u64 = 15 * 60;

/// Start PHP, bind the port, and serve until told to stop.
pub async fn run(cfg: Config) -> Result<()> {
    config::ensure_dirs()?;

    esw::log_line(&format!(
        "[{}] starting ember on {} with esw-engine {} in {} mode",
        daemon::now_secs(),
        cfg.addr(),
        cfg.esw_version,
        cfg.mode.as_str()
    ));

    // The engine comes up first: no point holding a port we cannot serve from.
    let engine = EswProcess::spawn(&cfg)
        .await
        .context("could not start esw-engine")?;

    let listener = tokio::net::TcpListener::bind(cfg.addr())
        .await
        .with_context(|| format!("could not bind {}", cfg.addr()))?;

    // Worker mode when the panel opts in by shipping bin/esw-worker.php;
    // otherwise fall back to FastCGI, which is what the placeholder needs.
    let panel_dir = config::panel_dir()?;
    let workers = if WorkerPool::script_path(&panel_dir).is_file() {
        match WorkerPool::start(&cfg, panel_dir.clone(), worker_count()).await {
            Ok(pool) => {
                esw::log_line(&format!(
                    "[{}] worker mode: {} resident symfony workers",
                    daemon::now_secs(),
                    pool.size()
                ));
                Some(pool)
            }
            Err(err) => {
                // Falling back keeps the panel reachable instead of failing to
                // boot, but this must be loud — it is a large silent slowdown.
                esw::log_line(&format!(
                    "[{}] worker mode unavailable, falling back to FastCGI: {err:#}",
                    daemon::now_secs()
                ));
                None
            }
        }
    } else {
        None
    };

    let state = AppState(Arc::new(Inner {
        public_dir: config::panel_public_dir()?,
        pool: engine.addr.clone(),
        host: cfg.host.clone(),
        port: cfg.port,
        esw_version: cfg.esw_version.clone(),
        mode: cfg.mode,
        started_at: daemon::now_secs(),
        workers: workers.clone(),
        throttle: std::sync::Mutex::new(HashMap::new()),
    }));

    let app = Router::new().fallback(handle).with_state(state);

    // Only now do we claim to be running.
    daemon::write_state(&ServiceState {
        pid: std::process::id() as i32,
        host: cfg.host.clone(),
        port: cfg.port,
        esw_version: cfg.esw_version.clone(),
        mode: cfg.mode.as_str().to_string(),
        started_at: daemon::now_secs(),
    })?;

    // Bring the database up if it is installed but idle. Deliberately after the
    // panel is already serving: a database that will not start is worth
    // reporting, not worth refusing to boot over.
    {
        let cfg = cfg.clone();
        tokio::task::spawn_blocking(move || {
            let status = database::ensure_running(&cfg);
            esw::log_line(&format!("[{}] database: {status}", daemon::now_secs()));

            // Site pools daemonise and outlive ember, so this reconciles with
            // whatever is already running rather than assuming.
            for message in php::reload_all(&cfg) {
                esw::log_line(&format!("[{}] php: {message}", daemon::now_secs()));
            }

            let web = vhost::ensure_running(&cfg);
            esw::log_line(&format!("[{}] web server: {web}", daemon::now_secs()));

            // Recreate system accounts the store knows about but the machine
            // does not. Replacing a container keeps the records on the volume
            // and discards /etc/passwd, which otherwise breaks the next thing
            // that touches the account with a message about the wrong problem.
            for message in reconcile_accounts(&cfg) {
                esw::log_line(&format!("[{}] accounts: {message}", daemon::now_secs()));
            }
        });
    }

    esw::log_line(&format!(
        "[{}] ready — panel at {}",
        daemon::now_secs(),
        cfg.url()
    ));

    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;

    esw::log_line(&format!("[{}] shutting down", daemon::now_secs()));
    if let Some(pool) = workers {
        pool.shutdown().await;
    }
    engine.shutdown().await;
    daemon::clear_state();

    result.context("http server error")
}

/// Resolve on SIGTERM (from `ember stop`) or Ctrl-C (foreground runs).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

async fn handle(State(state): State<AppState>, request: Request) -> Response {
    match route(state, request).await {
        Ok(response) => response,
        Err(err) => {
            esw::log_line(&format!("[{}] error: {err:#}", daemon::now_secs()));
            (StatusCode::BAD_GATEWAY, format!("ember: {err}\n")).into_response()
        }
    }
}

async fn route(state: AppState, request: Request) -> Result<Response> {
    let inner = &state.0;
    let uri_path = request.uri().path().to_string();
    let decoded = percent_decode(&uri_path);

    // Reject traversal before touching the filesystem.
    if decoded.split('/').any(|seg| seg == "..") {
        return Ok((StatusCode::BAD_REQUEST, "bad path\n").into_response());
    }

    // Liveness is deliberately unauthenticated: orchestrators must be able to
    // probe it, and it reveals nothing beyond "the process is up".
    if decoded == "/healthz" {
        return Ok((
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            serde_json::to_vec(&serde_json::json!({
                "status": "ok",
                "uptime_seconds": daemon::now_secs().saturating_sub(inner.started_at),
            }))?,
        )
            .into_response());
    }

    if decoded == "/logout" {
        return Ok(logout_response());
    }

    // Until an administrator exists there is nothing to sign in to, so every
    // route funnels into setup.
    let store = accounts::Store::load();
    if store.is_empty() {
        return match (decoded.as_str(), request.method()) {
            ("/setup", &Method::GET) => {
                Ok(html(StatusCode::OK, setup_page(&state, None, "admin", "")))
            }
            ("/setup", &Method::POST) => handle_setup(&state, request).await,
            _ => Ok(redirect("/setup")),
        };
    }

    // Setup is finished; do not let it be replayed.
    if decoded == "/setup" {
        return Ok(redirect("/login"));
    }

    if decoded == "/login" {
        // A one-time URL from `ember login` still works and skips the form.
        if request.uri().query().unwrap_or("").contains("token=") {
            return redeem_login(&request);
        }
        return match *request.method() {
            Method::GET => Ok(html(StatusCode::OK, pages::login(None, "", None))),
            Method::POST => handle_password_login(&state, request).await,
            _ => Ok((StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n").into_response()),
        };
    }

    let Some(user) = session_user(&request)? else {
        return Ok(unauthenticated_response());
    };

    // Ember's own control plane. Reserved before the filesystem is consulted so
    // a file dropped in `public/api/` can never shadow it. Privileged
    // operations live here because PHP runs unprivileged and must ask for them.
    if decoded == "/api/v1" || decoded.starts_with("/api/v1/") {
        return control_api(inner, request, &decoded, &user).await;
    }

    let relative = decoded.trim_start_matches('/');
    let candidate = inner.public_dir.join(relative);
    let is_php = candidate.extension().and_then(|e| e.to_str()) == Some("php");

    // Real, non-PHP files are served straight off disk.
    if !relative.is_empty() && !is_php && candidate.is_file() {
        return serve_static(&candidate).await;
    }

    // A directly requested .php file runs as itself; anything else falls
    // through to the front controller, which is what Symfony expects.
    let (script_path, script_name) = if is_php && candidate.is_file() {
        (candidate, decoded.clone())
    } else {
        (inner.public_dir.join("index.php"), "/index.php".to_string())
    };

    if !script_path.is_file() {
        return Ok((
            StatusCode::NOT_FOUND,
            format!(
                "ember: no panel application at {}\n\
                 install Symfony there, or restart ember to restore the placeholder.\n",
                inner.public_dir.display()
            ),
        )
            .into_response());
    }

    if let Some(pool) = inner.workers.clone() {
        return forward_to_worker(inner, pool, request, &decoded, &user).await;
    }

    forward_to_php(inner, request, &script_path, &script_name, &decoded, &user).await
}

/// Hand a request to a resident Symfony worker.
async fn forward_to_worker(
    inner: &Inner,
    pool: Arc<WorkerPool>,
    request: Request,
    document_uri: &str,
    user: &str,
) -> Result<Response> {
    let (parts, body) = request.into_parts();

    let uri = match parts.uri.path_and_query() {
        Some(pq) => pq.as_str().to_string(),
        None => document_uri.to_string(),
    };

    let body_bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .context("request body too large or unreadable")?;

    let mut headers = HashMap::new();
    let mut server = HashMap::new();
    for (name, value) in parts.headers.iter() {
        let Ok(value) = value.to_str() else { continue };
        let key = name.as_str().to_ascii_lowercase();
        // Identity is Ember's to state, never the client's.
        if key == "remote-user" {
            continue;
        }
        headers.insert(key.clone(), value.to_string());
        server.insert(
            format!("HTTP_{}", name.as_str().to_uppercase().replace('-', "_")),
            value.to_string(),
        );
    }

    let cookies = parts
        .headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|raw| {
            raw.split(';')
                .filter_map(|pair| pair.trim().split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();

    // The same CGI variables the FastCGI path sets, so the panel cannot tell
    // which transport carried the request.
    server.insert("REMOTE_USER".into(), user.to_string());
    server.insert("EMBER_USER".into(), user.to_string());
    server.insert("AUTH_TYPE".into(), "ember-session".into());
    server.insert(
        "SERVER_SOFTWARE".into(),
        concat!("ember/", env!("CARGO_PKG_VERSION")).into(),
    );
    server.insert("SERVER_NAME".into(), inner.host.clone());
    server.insert("SERVER_PORT".into(), inner.port.to_string());
    server.insert("REMOTE_ADDR".into(), "127.0.0.1".into());
    server.insert(
        "DOCUMENT_ROOT".into(),
        inner.public_dir.to_string_lossy().into_owned(),
    );

    let result = pool
        .handle(
            parts.method.as_str(),
            &uri,
            headers,
            cookies,
            server,
            body_bytes.to_vec(),
        )
        .await?;

    let mut builder = Response::builder()
        .status(StatusCode::from_u16(result.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    for (name, values) in result.headers {
        let Ok(header_name) = HeaderName::try_from(name.to_ascii_lowercase()) else {
            continue;
        };
        for value in values {
            if let Ok(header_value) = HeaderValue::from_str(&value) {
                builder = builder.header(header_name.clone(), header_value);
            }
        }
    }

    builder
        .body(Body::from(result.body))
        .context("could not build the worker response")
}

/// How many resident workers to run.
fn worker_count() -> usize {
    if let Ok(raw) = std::env::var("EMBER_WORKERS")
        && let Ok(count) = raw.parse::<usize>()
        && count > 0
    {
        return count;
    }
    // Modest by default: this is a control panel, not a public site, and each
    // worker holds a booted kernel in memory.
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(2, 4))
        .unwrap_or(2)
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

fn cookie_value(request: &Request, name: &str) -> Option<String> {
    request
        .headers()
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
}

fn session_user(request: &Request) -> Result<Option<String>> {
    match cookie_value(request, auth::SESSION_COOKIE) {
        Some(cookie) => auth::verify_session(&cookie),
        None => Ok(None),
    }
}

/// Exchange a one-time token from `ember login` for a session cookie.
fn redeem_login(request: &Request) -> Result<Response> {
    let token = request
        .uri()
        .query()
        .unwrap_or("")
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "token")
        .map(|(_, value)| percent_decode(value));

    let Some(token) = token else {
        return Ok(unauthenticated_response());
    };

    let Some(user) = auth::consume_login_token(&token)? else {
        return Ok((
            StatusCode::UNAUTHORIZED,
            "ember: this login link is invalid, expired, or already used.\n\
             run `ember login` again for a fresh one.\n",
        )
            .into_response());
    };

    let expires_at = daemon::now_secs() + auth::SESSION_TTL.as_secs();
    let cookie = format!(
        // No `Secure` yet — that arrives with TLS. HttpOnly keeps the session
        // out of reach of panel JavaScript either way.
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        auth::SESSION_COOKIE,
        auth::sign_session(&user, expires_at)?,
        auth::SESSION_TTL.as_secs()
    );

    esw::log_line(&format!(
        "[{}] login: {user} redeemed a one-time token",
        daemon::now_secs()
    ));

    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/")
        .header(header::SET_COOKIE, cookie)
        .body(Body::empty())
        .context("could not build login response")
}

fn logout_response() -> Response {
    let cookie = format!(
        "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        auth::SESSION_COOKIE
    );
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/")
        .header(header::SET_COOKIE, cookie)
        .body(Body::empty())
        .expect("static logout response is always valid")
}

// ---------------------------------------------------------------------------
// Setup and password sign-in
// ---------------------------------------------------------------------------

/// Parse an `application/x-www-form-urlencoded` body.
fn parse_form(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (form_decode(key), form_decode(value)))
        .collect()
}

/// Like percent decoding, but `+` also means space in form bodies.
fn form_decode(raw: &str) -> String {
    percent_decode(&raw.replace('+', " "))
}

async fn read_form(request: Request) -> Result<HashMap<String, String>> {
    let body = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .context("form body too large")?;
    Ok(parse_form(&String::from_utf8_lossy(&body)))
}

/// Ember can only create a real system account when it is allowed to modify the
/// machine *and* has the privilege to do so.
fn can_create_system_user(state: &AppState) -> bool {
    state.0.mode == config::Mode::Host && auth::running_as_root()
}

fn setup_page(state: &AppState, error: Option<&str>, username: &str, email: &str) -> String {
    pages::setup(error, username, email, can_create_system_user(state))
}

async fn handle_setup(state: &AppState, request: Request) -> Result<Response> {
    let form = read_form(request).await?;
    let username = form.get("username").map(String::as_str).unwrap_or("admin");
    let email = form.get("email").map(String::as_str).unwrap_or("");
    let password = form.get("password").map(String::as_str).unwrap_or("");
    let confirm = form.get("confirm").map(String::as_str).unwrap_or("");

    let fail = |message: String| -> Result<Response> {
        Ok(html(
            StatusCode::BAD_REQUEST,
            setup_page(state, Some(&message), username, email),
        ))
    };

    if password != confirm {
        return fail("The two passwords do not match.".to_string());
    }
    if let Err(err) = accounts::check_username(username) {
        return fail(err.to_string());
    }
    if let Err(err) = accounts::check_password_strength(password) {
        return fail(err.to_string());
    }

    let mut store = accounts::Store::load();
    if !store.is_empty() {
        return Ok(redirect("/login"));
    }

    // A system-backed admin is preferable — the password then lives in the
    // system database and every other tool agrees about it. Fall back to a
    // local account when Ember is not permitted to touch this machine.
    let mut source = Source::Local;
    if can_create_system_user(state) {
        if auth::system_user_exists(username) {
            // Adopt the existing account rather than trying to recreate it.
            source = Source::System;
        } else {
            match auth::create_system_user(username, "/bin/bash") {
                Ok(()) => match auth::set_system_password(username, password) {
                    Ok(()) => source = Source::System,
                    Err(err) => {
                        esw::log_line(&format!(
                            "setup: created {username} but could not set its password: {err:#}"
                        ));
                        return fail(format!(
                            "Created the system account but could not set its password: {err}"
                        ));
                    }
                },
                Err(err) => {
                    esw::log_line(&format!("setup: could not create system user: {err:#}"));
                    return fail(format!("Could not create the system account: {err}"));
                }
            }
        }
    }

    let email = (!email.trim().is_empty()).then(|| email.trim().to_string());
    let email_for_customer = email.clone();
    if let Err(err) = store.create_admin(username, password, email, None, source) {
        return fail(err.to_string());
    }

    // The administrator is also a customer, so their own sites have somewhere
    // to hang without inventing a second account first. Failing here is not
    // worth blocking setup over — the customer can be added later.
    if let Ok(conn) = store::open()
        && store::list_customers(&conn)
            .map(|customers| customers.iter().all(|c| c.username != username))
            .unwrap_or(false)
        && let Err(err) =
            store::create_customer(&conn, username, None, email_for_customer.as_deref())
    {
        esw::log_line(&format!(
            "setup: could not add {username} as a customer: {err}"
        ));
    }

    esw::log_line(&format!(
        "[{}] setup: administrator {username:?} created ({:?})",
        daemon::now_secs(),
        source
    ));

    issue_session(username)
}

async fn handle_password_login(state: &AppState, request: Request) -> Result<Response> {
    let form = read_form(request).await?;
    let username = form
        .get("username")
        .map(|u| u.trim().to_string())
        .unwrap_or_default();
    let password = form.get("password").cloned().unwrap_or_default();

    // Deliberately identical for "no such account" and "wrong password" so the
    // form cannot be used to enumerate usernames.
    let generic = "Incorrect username or password.";

    if let Some(remaining) = locked_for(state, &username) {
        let minutes = remaining.div_ceil(60);
        return Ok(html(
            StatusCode::TOO_MANY_REQUESTS,
            pages::login(
                Some(&format!(
                    "Too many failed attempts. Try again in {minutes} minute(s), or run `ember recover` on the server."
                )),
                &username,
                None,
            ),
        ));
    }

    let store = accounts::Store::load();
    let verified = match store.get(&username) {
        Some(account) => match account.verify_password(&password) {
            Ok(ok) => ok,
            Err(err) => {
                // A broken PAM stack must not be reported as a bad password.
                esw::log_line(&format!("login: {username} could not be verified: {err:#}"));
                return Ok(html(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    pages::login(
                        Some("Authentication is misconfigured on this server. See `ember logs`."),
                        &username,
                        None,
                    ),
                ));
            }
        },
        None => {
            // Spend comparable effort on unknown users so response time does
            // not reveal whether the account exists.
            let _ = accounts::hash_password(&password);
            false
        }
    };

    if !verified {
        record_failure(state, &username);
        esw::log_line(&format!(
            "[{}] login: failed attempt for {username:?}",
            daemon::now_secs()
        ));
        return Ok(html(
            StatusCode::UNAUTHORIZED,
            pages::login(Some(generic), &username, None),
        ));
    }

    clear_failures(state, &username);
    esw::log_line(&format!(
        "[{}] login: {username} signed in with a password",
        daemon::now_secs()
    ));
    issue_session(&username)
}

/// Mint the session cookie and send the browser to the panel.
fn issue_session(username: &str) -> Result<Response> {
    let expires_at = daemon::now_secs() + auth::SESSION_TTL.as_secs();
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        auth::SESSION_COOKIE,
        auth::sign_session(username, expires_at)?,
        auth::SESSION_TTL.as_secs()
    );
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/")
        .header(header::SET_COOKIE, cookie)
        .body(Body::empty())
        .context("could not build session response")
}

/// Seconds remaining on a lockout, if one is in force.
fn locked_for(state: &AppState, username: &str) -> Option<u64> {
    let throttle = state.0.throttle.lock().ok()?;
    let attempts = throttle.get(username)?;
    let now = daemon::now_secs();
    (attempts.locked_until > now).then(|| attempts.locked_until - now)
}

fn record_failure(state: &AppState, username: &str) {
    let Ok(mut throttle) = state.0.throttle.lock() else {
        return;
    };
    let entry = throttle.entry(username.to_string()).or_insert(Attempts {
        count: 0,
        locked_until: 0,
    });
    entry.count += 1;
    if entry.count >= MAX_ATTEMPTS {
        entry.count = 0;
        entry.locked_until = daemon::now_secs() + LOCKOUT_SECS;
    }
}

fn clear_failures(state: &AppState, username: &str) {
    if let Ok(mut throttle) = state.0.throttle.lock() {
        throttle.remove(username);
    }
}

// ---------------------------------------------------------------------------
// Control API
// ---------------------------------------------------------------------------

/// Ember's privileged control plane, served by Rust rather than PHP.
///
/// The Symfony panel calls these endpoints for anything it cannot do itself —
/// the PHP pool runs unprivileged by design, so system-level work is delegated
/// here rather than handed to the web tier.
async fn control_api(inner: &Inner, request: Request, path: &str, user: &str) -> Result<Response> {
    let method = request.method().clone();
    let route = path.trim_end_matches('/');

    // Anything that changes the machine is admin-only. Reads are open to any
    // signed-in account so the panel can render without elevated rights.
    if method != Method::GET && !is_admin(user) {
        return Ok(api_error(
            StatusCode::FORBIDDEN,
            "this action requires an administrator",
        ));
    }

    if let Some(response) = resource_api(inner, &method, route, request, user).await? {
        return Ok(response);
    }

    let body = match route {
        "/api/v1" => serde_json::json!({
            "service": "ember",
            "version": env!("CARGO_PKG_VERSION"),
            "endpoints": [
                "/api/v1/status", "/api/v1/whoami", "/api/v1/users",
                "/api/v1/summary", "/api/v1/customers", "/api/v1/domains",
                "/api/v1/branding", "/api/v1/databases",
                "/api/v1/domains/{id}/certificate",
                "/api/v1/certificates/renew", "/api/v1/services",
                "/api/v1/system", "/api/v1/updates", "/api/v1/jobs",
            ],
        }),
        "/api/v1/status" => serde_json::json!({
            "status": "running",
            "mode": inner.mode.as_str(),
            "manages_this_machine": inner.mode == config::Mode::Host,
            "pid": std::process::id(),
            "host": inner.host,
            "port": inner.port,
            "uptime_seconds": daemon::now_secs().saturating_sub(inner.started_at),
            "engine": {
                "name": "esw-engine",
                "version": inner.esw_version,
                "pool": inner.pool.describe(),
                "mode": if inner.workers.is_some() { "worker" } else { "fastcgi" },
                "workers": inner.workers.as_ref().map(|p| p.size()),
            },
            "panel_root": inner.public_dir.to_string_lossy(),
        }),
        // Read-only: the panel lists accounts in either mode. Creating one is a
        // mutation and lives behind the CLI's host-mode gate.
        "/api/v1/users" => serde_json::json!({
            "users": auth::list_system_users(1000),
        }),
        "/api/v1/whoami" => serde_json::json!({
            "user": user,
            "system_user": auth::system_user_exists(user),
            "home": auth::system_user_home(user).map(|p| p.to_string_lossy().into_owned()),
            "is_root": user == "root",
        }),
        _ => {
            return Ok((
                StatusCode::NOT_FOUND,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )],
                serde_json::to_vec(&serde_json::json!({ "error": "unknown endpoint" }))?,
            )
                .into_response());
        }
    };

    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        serde_json::to_vec_pretty(&body)?,
    )
        .into_response())
}

/// Send a browser to the login page rather than a bare 401 — a blank 401 reads
/// as a broken panel.
/// Take a multipart upload and store every file it carries.
///
/// Browsers cannot send anything but a form here, so on success this answers
/// with a redirect when the form asked for one, and JSON otherwise — the same
/// endpoint serves a person and a script.
async fn upload(
    cfg: &Config,
    domain: &store::Domain,
    request: Request,
    actor: &str,
) -> Result<Response> {
    use axum::extract::Multipart;

    let mut multipart = match Multipart::from_request(request, &()).await {
        Ok(multipart) => multipart,
        Err(err) => {
            return Ok(api_error(
                StatusCode::BAD_REQUEST,
                &format!("could not read the upload: {err}"),
            ));
        }
    };

    let mut directory = "/".to_string();
    let mut redirect_to: Option<String> = None;
    let mut saved: Vec<String> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name().unwrap_or("").to_string().as_str() {
            "path" => directory = field.text().await.unwrap_or_default(),
            "redirect" => redirect_to = field.text().await.ok(),
            "file" | "files" | "files[]" => {
                let filename = field.file_name().unwrap_or("").to_string();
                if filename.is_empty() {
                    continue; // An empty file input still sends a part.
                }
                match field.bytes().await {
                    Ok(bytes) => {
                        match files::save_upload(cfg, domain, &directory, &filename, &bytes) {
                            Ok(path) => saved.push(path),
                            Err(err) => failures.push(format!("{filename}: {err}")),
                        }
                    }
                    Err(err) => failures.push(format!("{filename}: {err}")),
                }
            }
            _ => {}
        }
    }

    if !saved.is_empty() {
        esw::log_line(&format!(
            "[{}] {actor} uploaded {} file(s) to {}",
            daemon::now_secs(),
            saved.len(),
            domain.name
        ));
    }

    if let Some(target) = redirect_to {
        // Only same-origin paths, so a crafted form cannot bounce the operator
        // somewhere else after an upload.
        let safe = target.starts_with('/') && !target.starts_with("//");
        return Ok(redirect(if safe { &target } else { "/" }));
    }

    Ok(api_json(
        if failures.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::BAD_REQUEST
        },
        serde_json::json!({ "saved": saved, "failed": failures }),
    ))
}

/// Put back system accounts that the store expects and the machine lacks.
fn reconcile_accounts(cfg: &Config) -> Vec<String> {
    if cfg.mode != config::Mode::Host {
        return Vec::new();
    }

    let Ok(conn) = store::open() else {
        return vec!["could not open the store".into()];
    };
    let Ok(missing) = store::customers_missing_accounts(&conn) else {
        return vec!["could not check for missing accounts".into()];
    };
    if missing.is_empty() {
        return Vec::new();
    }

    missing
        .into_iter()
        .map(|customer| {
            // No login shell: a recreated hosting account should be no more
            // privileged than a fresh one, and shell access is a setting.
            match auth::create_system_user(&customer.username, "/usr/sbin/nologin") {
                Ok(()) => format!("recreated missing system account {}", customer.username),
                Err(err) => format!("could not recreate {}: {err}", customer.username),
            }
        })
        .collect()
}

/// A domain's hosting settings, or the defaults when it has none.
fn hosting_of(domain: &store::Domain) -> vhost::HostingSettings {
    domain
        .hosting_settings
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

/// Overlay submitted fields onto the stored settings.
///
/// A form that posts only what it shows must not reset the rest, so absent keys
/// keep their current value rather than falling back to the default.
fn merge_settings(mut base: serde_json::Value, incoming: serde_json::Value) -> serde_json::Value {
    let (Some(base_map), Some(incoming_map)) = (base.as_object_mut(), incoming.as_object()) else {
        return base;
    };
    for (key, value) in incoming_map {
        if base_map.contains_key(key) && !value.is_null() {
            base_map.insert(key.clone(), value.clone());
        }
    }
    base
}

/// Is this account allowed to change the machine?
fn is_admin(user: &str) -> bool {
    if user == "root" {
        return true;
    }
    accounts::Store::load()
        .get(user)
        .map(|account| account.is_admin)
        .unwrap_or(false)
}

fn api_json(status: StatusCode, body: serde_json::Value) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        serde_json::to_vec_pretty(&body).unwrap_or_default(),
    )
        .into_response()
}

fn api_error(status: StatusCode, message: &str) -> Response {
    api_json(status, serde_json::json!({ "error": message }))
}

/// Parse `/api/v1/<collection>/<id>` into its parts.
fn path_id(route: &str, prefix: &str) -> Option<i64> {
    route.strip_prefix(prefix)?.trim_matches('/').parse().ok()
}

async fn json_body(request: Request) -> Result<serde_json::Value> {
    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .context("request body too large")?;
    if bytes.is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_slice(&bytes).context("request body is not valid JSON")
}

fn field<'a>(body: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    body.get(name)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Customers and domains. Returns `Ok(None)` when the route is not one of ours,
/// so the caller can fall through to the informational endpoints.
async fn resource_api(
    inner: &Inner,
    method: &Method,
    route: &str,
    request: Request,
    actor: &str,
) -> Result<Option<Response>> {
    let cfg = Config {
        host: inner.host.clone(),
        port: inner.port,
        esw_version: inner.esw_version.clone(),
        mode: inner.mode,
    };

    let response = match (method, route) {
        // The panel renders its own chrome, so it needs the same branding the
        // sign-in page uses. Readable by any signed-in account.
        (&Method::GET, "/api/v1/branding") => {
            let branding = config::Branding::resolve();
            api_json(
                StatusCode::OK,
                serde_json::json!({
                    "name": branding.name,
                    "tagline": branding.tagline,
                    "accent": branding.safe_accent(),
                    "logo_url": branding.logo_url,
                    "env_overrides": config::Branding::env_overrides(),
                }),
            )
        }

        (&Method::GET, "/api/v1/summary") => {
            let conn = store::open()?;
            api_json(StatusCode::OK, store::summary(&conn)?)
        }

        // --- customers -----------------------------------------------------
        (&Method::GET, "/api/v1/customers") => {
            let conn = store::open()?;
            api_json(
                StatusCode::OK,
                serde_json::json!({ "customers": store::list_customers(&conn)? }),
            )
        }

        (&Method::GET, r) if path_id(r, "/api/v1/customers").is_some() => {
            let id = path_id(r, "/api/v1/customers").unwrap();
            let conn = store::open()?;
            match store::find_customer(&conn, id)? {
                Some(customer) => api_json(StatusCode::OK, serde_json::json!(customer)),
                None => api_error(StatusCode::NOT_FOUND, "no such customer"),
            }
        }

        (&Method::POST, "/api/v1/customers") => {
            let body = json_body(request).await?;
            let Some(username) = field(&body, "username") else {
                return Ok(Some(api_error(
                    StatusCode::BAD_REQUEST,
                    "username is required",
                )));
            };

            // The system account comes first: if it cannot be created there is
            // no point recording a customer that owns nothing.
            if cfg.mode == config::Mode::Host
                && !auth::system_user_exists(username)
                && let Err(err) = auth::create_system_user(username, "/usr/sbin/nologin")
            {
                return Ok(Some(api_error(
                    StatusCode::BAD_REQUEST,
                    &format!("could not create the system account: {err}"),
                )));
            }

            let conn = store::open()?;
            match store::create_customer(
                &conn,
                username,
                field(&body, "display_name"),
                field(&body, "email"),
            ) {
                Ok(customer) => {
                    // The webspace exists from the moment the customer does,
                    // so there is somewhere to put files before a domain is
                    // added rather than only afterwards.
                    let mut notes = Vec::new();
                    if cfg.mode == config::Mode::Host {
                        match vhost::create_webspace(&cfg, username) {
                            Ok(path) => notes.push(format!("webspace {path}")),
                            Err(err) => notes.push(format!("webspace not created: {err}")),
                        }
                    }

                    esw::log_line(&format!(
                        "[{}] {actor} created customer {username}",
                        daemon::now_secs()
                    ));
                    api_json(
                        StatusCode::CREATED,
                        serde_json::json!({
                            "id": customer.id,
                            "username": customer.username,
                            "display_name": customer.display_name,
                            "email": customer.email,
                            "status": customer.status,
                            "created_at": customer.created_at,
                            "domain_count": customer.domain_count,
                            "notes": notes,
                        }),
                    )
                }
                Err(err) => api_error(StatusCode::BAD_REQUEST, &err.to_string()),
            }
        }

        (&Method::DELETE, r) if path_id(r, "/api/v1/customers").is_some() => {
            let id = path_id(r, "/api/v1/customers").unwrap();
            let conn = store::open()?;
            match store::delete_customer(&conn, id) {
                Ok(customer) => {
                    esw::log_line(&format!(
                        "[{}] {actor} removed customer {}",
                        daemon::now_secs(),
                        customer.username
                    ));
                    // The system account is deliberately left in place: it may
                    // own files elsewhere, and removing accounts is not
                    // something to do as a side effect.
                    api_json(
                        StatusCode::OK,
                        serde_json::json!({
                            "removed": customer.username,
                            "note": "the system account was kept; remove it manually if unused",
                        }),
                    )
                }
                Err(err) => api_error(StatusCode::BAD_REQUEST, &err.to_string()),
            }
        }

        // --- domains -------------------------------------------------------
        (&Method::GET, "/api/v1/domains") => {
            // ?customer_id=N narrows the list, so the customer page does not
            // have to fetch everything and filter in the view.
            let customer_id = request
                .uri()
                .query()
                .unwrap_or("")
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(k, _)| *k == "customer_id")
                .and_then(|(_, v)| v.parse::<i64>().ok());

            let conn = store::open()?;
            api_json(
                StatusCode::OK,
                serde_json::json!({ "domains": store::list_domains(&conn, customer_id)? }),
            )
        }

        (&Method::GET, r) if path_id(r, "/api/v1/domains").is_some() => {
            let id = path_id(r, "/api/v1/domains").unwrap();
            let conn = store::open()?;
            match store::find_domain(&conn, id)? {
                Some(domain) => api_json(StatusCode::OK, serde_json::json!(domain)),
                None => api_error(StatusCode::NOT_FOUND, "no such domain"),
            }
        }

        (&Method::POST, "/api/v1/domains") => {
            let body = json_body(request).await?;
            let Some(name) = field(&body, "name") else {
                return Ok(Some(api_error(StatusCode::BAD_REQUEST, "name is required")));
            };
            let Some(customer_id) = body.get("customer_id").and_then(|v| v.as_i64()) else {
                return Ok(Some(api_error(
                    StatusCode::BAD_REQUEST,
                    "customer_id is required",
                )));
            };
            let webserver = field(&body, "webserver").unwrap_or("nginx");

            let conn = store::open()?;
            let domain = match store::create_domain(&conn, customer_id, name, webserver) {
                Ok(domain) => domain,
                Err(err) => {
                    return Ok(Some(api_error(StatusCode::BAD_REQUEST, &err.to_string())));
                }
            };

            // Lay out the files and write the vhost. In isolated mode this is
            // refused, and the record is rolled back rather than left claiming
            // a domain that has nothing behind it.
            let owner = domain.customer_username.clone().unwrap_or_default();
            let mut warnings = Vec::new();
            if cfg.mode == config::Mode::Host {
                if let Err(err) = vhost::provision(&cfg, &domain, &owner) {
                    let _ = store::delete_domain(&conn, domain.id);
                    return Ok(Some(api_error(
                        StatusCode::BAD_REQUEST,
                        &format!("could not create the hosting layout: {err}"),
                    )));
                }
                // The vhost points PHP at a pool socket, so the pool has to
                // exist before the site is reloadable.
                match php::apply(&cfg, &domain, &php::PhpSettings::default()) {
                    Ok(message) => warnings.push(message),
                    Err(err) => warnings.push(format!("php pool not created: {err}")),
                }
                match vhost::write_config(&cfg, &domain, &hosting_of(&domain)) {
                    Ok(path) => warnings.push(format!("config written to {}", path.display())),
                    Err(err) => warnings.push(format!("config not written: {err}")),
                }
                if let Ok(server) = vhost::WebServer::parse(&domain.webserver) {
                    warnings.push(vhost::reload(server)?);
                }
            } else {
                warnings.push(
                    "isolated mode: the record was created but no files or vhost were written"
                        .to_string(),
                );
            }

            esw::log_line(&format!(
                "[{}] {actor} created domain {name} for {owner}",
                daemon::now_secs()
            ));
            api_json(
                StatusCode::CREATED,
                serde_json::json!({ "domain": domain, "notes": warnings }),
            )
        }

        // --- settings: services, updates, the machine ----------------------
        (&Method::GET, "/api/v1/services") => api_json(
            StatusCode::OK,
            serde_json::json!({
                "services": services::list(),
                "engines": system::engine_versions().unwrap_or_default(),
                "node_versions": services::node_versions(),
                "node_installed": services::node_version(),
            }),
        ),

        (&Method::POST, "/api/v1/services/install") => {
            let body = json_body(request).await?;

            // Installing an engine version is ember's own business; everything
            // else is a distribution package.
            if let Some(version) = field(&body, "engine") {
                if !system::AVAILABLE_ENGINES
                    .iter()
                    .any(|(candidate, _, _)| *candidate == version)
                {
                    return Ok(Some(api_error(
                        StatusCode::BAD_REQUEST,
                        "unknown engine version",
                    )));
                }
                let version = version.to_string();
                return Ok(Some(
                    match tokio::task::spawn_blocking(move || esw::install(&version, false)).await?
                    {
                        Ok(path) => api_json(
                            StatusCode::OK,
                            serde_json::json!({ "installed": path.to_string_lossy() }),
                        ),
                        Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
                    },
                ));
            }

            // Queued rather than run inline: an install takes minutes, and
            // holding the request open for it tells the operator nothing about
            // whether it is working or stuck.
            let work = if let Some(major) = field(&body, "node") {
                if !services::AVAILABLE_NODE
                    .iter()
                    .any(|(known, _, _)| *known == major)
                {
                    return Ok(Some(api_error(
                        StatusCode::BAD_REQUEST,
                        "unknown Node version",
                    )));
                }
                jobs::Work::InstallNode(major.to_string())
            } else if let Some(id) = field(&body, "id") {
                jobs::Work::InstallService(id.to_string())
            } else {
                return Ok(Some(api_error(StatusCode::BAD_REQUEST, "id is required")));
            };

            let job = jobs::submit(&cfg, work);
            esw::log_line(&format!(
                "[{}] {actor} queued job {}: {}",
                daemon::now_secs(),
                job.id,
                job.label
            ));
            api_json(StatusCode::ACCEPTED, serde_json::json!({ "job": job }))
        }

        // What the queue is doing. Polled by the UI while anything is in flight.
        (&Method::GET, "/api/v1/jobs") => api_json(
            StatusCode::OK,
            serde_json::json!({
                "jobs": jobs::list(&cfg),
                "busy": jobs::busy(&cfg),
                "package_lock_held_by": jobs::package_lock_holder(),
            }),
        ),

        // Server-level view of the database engines, for Settings. Distinct
        // from /api/v1/databases, which is about a customer's databases.
        (&Method::GET, "/api/v1/database-servers") => {
            let conn = store::open()?;
            let all = store::list_databases(&conn, None, None)?;

            let servers: Vec<serde_json::Value> = [
                (database::Engine::MariaDb, "MariaDB", "mariadb"),
                (database::Engine::Postgres, "PostgreSQL", "postgresql"),
            ]
            .iter()
            .map(|(engine, name, service_id)| {
                let (up, status) = database::engine_status(*engine);
                let count = all.iter().filter(|d| d.engine == engine.as_str()).count();
                serde_json::json!({
                    "engine": engine.as_str(),
                    "name": name,
                    "service_id": service_id,
                    "available": up,
                    "status": status,
                    "databases": count,
                    "can_create": true,
                })
            })
            .collect();

            let redis = services::list()
                .into_iter()
                .find(|s| s.id == "redis")
                .map(|s| (s.installed, s.running));

            api_json(
                StatusCode::OK,
                serde_json::json!({
                    "servers": servers,
                    "redis": redis.map(|(installed, running)| serde_json::json!({
                        "engine": "redis",
                        "name": "Redis",
                        "service_id": "redis",
                        "available": running,
                        "status": if installed {
                            if running { "running" } else { "installed, stopped" }
                        } else { "not installed" },
                        "databases": 0,
                        // Redis has no databases to create; the panel should not
                        // imply otherwise.
                        "can_create": false,
                    })),
                }),
            )
        }

        (&Method::GET, "/api/v1/system") => api_json(
            StatusCode::OK,
            serde_json::json!({
                "stats": system::stats(),
                "mode": inner.mode.as_str(),
            }),
        ),

        (&Method::GET, "/api/v1/updates") => {
            let repo = std::env::var("EMBER_REPO").unwrap_or_else(|_| "KumaVolt/ember".into());
            let (available, detail) = tokio::task::spawn_blocking(services::system_updates).await?;
            let ember =
                tokio::task::spawn_blocking(move || services::check_for_update(&repo)).await?;

            api_json(
                StatusCode::OK,
                serde_json::json!({
                    "ember": ember,
                    "system": { "updates_available": available, "detail": detail },
                }),
            )
        }

        (&Method::POST, "/api/v1/system/power") => {
            let body = json_body(request).await?;
            let action = match system::PowerAction::parse(field(&body, "action").unwrap_or("")) {
                Ok(action) => action,
                Err(err) => return Ok(Some(api_error(StatusCode::BAD_REQUEST, &err.to_string()))),
            };
            let confirm = field(&body, "confirm").unwrap_or("");

            match system::power(&cfg, action, confirm) {
                Ok(message) => api_json(StatusCode::OK, serde_json::json!({ "result": message })),
                Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
            }
        }

        (&Method::POST, "/api/v1/branding") => {
            let body = json_body(request).await?;
            let mut branding = config::Branding::resolve();

            if let Some(name) = field(&body, "name") {
                branding.name = name.to_string();
            }
            if let Some(tagline) = field(&body, "tagline") {
                branding.tagline = tagline.to_string();
            }
            if let Some(accent) = field(&body, "accent") {
                branding.accent = accent.to_string();
            }
            branding.logo_url = field(&body, "logo_url").map(str::to_string);

            // Validate before writing, so a bad colour cannot be persisted and
            // then break every page.
            if branding.safe_accent() != branding.accent.trim() {
                return Ok(Some(api_error(
                    StatusCode::BAD_REQUEST,
                    "that accent colour is not a usable CSS colour",
                )));
            }
            if branding.name.trim().is_empty() {
                return Ok(Some(api_error(StatusCode::BAD_REQUEST, "name is required")));
            }

            match branding.save() {
                Ok(()) => {
                    esw::log_line(&format!(
                        "[{}] {actor} updated branding",
                        daemon::now_secs()
                    ));
                    api_json(
                        StatusCode::OK,
                        serde_json::json!({
                            "branding": branding,
                            "env_overrides": config::Branding::env_overrides(),
                        }),
                    )
                }
                Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
            }
        }

        // --- databases -----------------------------------------------------
        (&Method::GET, "/api/v1/databases") => {
            let customer_id = request
                .uri()
                .query()
                .unwrap_or("")
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(k, _)| *k == "customer_id")
                .and_then(|(_, v)| v.parse::<i64>().ok());

            let domain_id = request
                .uri()
                .query()
                .unwrap_or("")
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(k, _)| *k == "domain_id")
                .and_then(|(_, v)| v.parse::<i64>().ok());

            let conn = store::open()?;
            let mut records = store::list_databases(&conn, customer_id, domain_id)?;

            // Sizes come from the server, not the record, so they cannot go
            // stale. Asked per engine, and skipped for any that is down.
            for record in &mut records {
                if let Ok(engine) = database::Engine::parse(&record.engine)
                    && database::engine_status(engine).0
                {
                    record.size_bytes = database::size_bytes_on(engine, &record.name);
                }
            }

            let (up, status) = database::server_status();
            api_json(
                StatusCode::OK,
                serde_json::json!({
                    "databases": records,
                    // Kept for the existing UI, which asks about the default.
                    "server": { "available": up, "status": status },
                    "engines": database::available_engines(),
                }),
            )
        }

        (&Method::POST, "/api/v1/databases") => {
            let body = json_body(request).await?;
            let engine = match database::Engine::parse(field(&body, "engine").unwrap_or("mariadb"))
            {
                Ok(engine) => engine,
                Err(err) => return Ok(Some(api_error(StatusCode::BAD_REQUEST, &err.to_string()))),
            };
            let Some(raw_name) = field(&body, "name") else {
                return Ok(Some(api_error(StatusCode::BAD_REQUEST, "name is required")));
            };
            let domain_id = body.get("domain_id").and_then(|v| v.as_i64());
            let conn = store::open()?;

            // Creating from a domain page need only name the domain; the owner
            // follows from it.
            let customer_id = match body.get("customer_id").and_then(|v| v.as_i64()) {
                Some(id) => id,
                None => match domain_id.and_then(|id| store::find_domain(&conn, id).ok().flatten())
                {
                    Some(domain) => domain.customer_id,
                    None => {
                        return Ok(Some(api_error(
                            StatusCode::BAD_REQUEST,
                            "customer_id or domain_id is required",
                        )));
                    }
                },
            };

            let Some(customer) = store::find_customer(&conn, customer_id)? else {
                return Ok(Some(api_error(StatusCode::NOT_FOUND, "no such customer")));
            };

            // Prefixed with the owner so two customers can both want the name
            // "wordpress", and so ownership is legible on the server itself.
            let name = database::qualified_name(&customer.username, raw_name);
            let user = field(&body, "user")
                .map(|u| u.to_string())
                .unwrap_or_else(|| {
                    database::qualified_name(&customer.username, raw_name)
                        .chars()
                        .take(database::MAX_DB_USER)
                        .collect()
                });

            let password = match field(&body, "password") {
                Some(given) => given.to_string(),
                None => match database::generate_password() {
                    Ok(generated) => generated,
                    Err(err) => {
                        return Ok(Some(api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &err.to_string(),
                        )));
                    }
                },
            };

            if let Err(err) = database::create(&cfg, engine, &name, &user, &password) {
                return Ok(Some(api_error(
                    StatusCode::BAD_REQUEST,
                    &format!("{err:#}"),
                )));
            }

            let record = match store::create_database_record(
                &conn,
                customer_id,
                engine.as_str(),
                &name,
                &user,
                domain_id,
            ) {
                Ok(record) => record,
                Err(err) => {
                    // The record is the only thing that knows this database
                    // belongs to us, so a failure here must not leave one
                    // orphaned on the server.
                    let _ = database::drop(&cfg, engine, &name, &user);
                    return Ok(Some(api_error(StatusCode::BAD_REQUEST, &err.to_string())));
                }
            };

            // Stored encrypted so it can be shown again. Failing to store is
            // not a reason to fail the creation — the database exists and the
            // password was just displayed.
            match secrets::seal(&password) {
                Ok(sealed) => {
                    let _ = store::set_database_password(&conn, record.id, &sealed);
                }
                Err(err) => esw::log_line(&format!("could not store the password: {err:#}")),
            }

            esw::log_line(&format!(
                "[{}] {actor} created database {name} for {}",
                daemon::now_secs(),
                customer.username
            ));

            // The password is returned exactly once: it is not stored, and it
            // cannot be recovered afterwards, only reset.
            api_json(
                StatusCode::CREATED,
                serde_json::json!({
                    "database": record,
                    "password": password,
                    "note": "this password is shown once and is not stored",
                }),
            )
        }

        (&Method::POST, r) if r.starts_with("/api/v1/databases/") && r.ends_with("/password") => {
            let id: i64 = r
                .trim_start_matches("/api/v1/databases/")
                .trim_end_matches("/password")
                .trim_matches('/')
                .parse()
                .unwrap_or(-1);

            let conn = store::open()?;
            let Some(record) = store::find_database(&conn, id)? else {
                return Ok(Some(api_error(StatusCode::NOT_FOUND, "no such database")));
            };
            let engine = database::Engine::parse(&record.engine)?;

            let body = json_body(request).await.unwrap_or(serde_json::json!({}));
            let password = match field(&body, "password") {
                Some(given) => given.to_string(),
                None => database::generate_password()?,
            };

            match database::set_password(&cfg, engine, &record.db_user, &password) {
                Ok(()) => {
                    if let Ok(sealed) = secrets::seal(&password) {
                        let _ = store::set_database_password(&conn, record.id, &sealed);
                    }
                    esw::log_line(&format!(
                        "[{}] {actor} reset the password for {}",
                        daemon::now_secs(),
                        record.db_user
                    ));
                    api_json(
                        StatusCode::OK,
                        serde_json::json!({ "user": record.db_user, "password": password }),
                    )
                }
                Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
            }
        }

        // Show a stored password.
        //
        // Admin-only and logged: reading out a credential is an event worth a
        // trail, even though the account doing it could reset the password
        // anyway.
        (&Method::GET, r) if r.starts_with("/api/v1/databases/") && r.ends_with("/reveal") => {
            let id: i64 = r
                .trim_start_matches("/api/v1/databases/")
                .trim_end_matches("/reveal")
                .trim_matches('/')
                .parse()
                .unwrap_or(-1);

            if !is_admin(actor) {
                return Ok(Some(api_error(
                    StatusCode::FORBIDDEN,
                    "only an administrator can read a stored password",
                )));
            }

            let conn = store::open()?;
            let Some(record) = store::find_database(&conn, id)? else {
                return Ok(Some(api_error(StatusCode::NOT_FOUND, "no such database")));
            };

            match store::database_password(&conn, id)? {
                Some(sealed) => match secrets::open(&sealed) {
                    Ok(password) => {
                        esw::log_line(&format!(
                            "[{}] {actor} viewed the password for {}",
                            daemon::now_secs(),
                            record.db_user
                        ));
                        api_json(
                            StatusCode::OK,
                            serde_json::json!({ "user": record.db_user, "password": password }),
                        )
                    }
                    Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
                },
                None => api_error(
                    StatusCode::NOT_FOUND,
                    "no password is stored for this database — it predates storage, or \
                     storing it failed. Reset it to store one.",
                ),
            }
        }

        // What this user can actually reach, asked of the server rather than
        // asserted by the panel.
        (&Method::GET, r) if r.starts_with("/api/v1/databases/") && r.ends_with("/grants") => {
            let id: i64 = r
                .trim_start_matches("/api/v1/databases/")
                .trim_end_matches("/grants")
                .trim_matches('/')
                .parse()
                .unwrap_or(-1);
            let conn = store::open()?;
            match store::find_database(&conn, id)? {
                Some(record) => api_json(
                    StatusCode::OK,
                    serde_json::json!({
                        "user": record.db_user,
                        "grants": database::Engine::parse(&record.engine)
                            .and_then(|engine| database::grants_for_on(engine, &record.db_user))
                            .unwrap_or_default(),
                    }),
                ),
                None => api_error(StatusCode::NOT_FOUND, "no such database"),
            }
        }

        (&Method::DELETE, r) if path_id(r, "/api/v1/databases").is_some() => {
            let id = path_id(r, "/api/v1/databases").unwrap();

            let confirm = request
                .uri()
                .query()
                .unwrap_or("")
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(k, _)| *k == "confirm")
                .map(|(_, v)| percent_decode(v));

            let conn = store::open()?;
            let Some(record) = store::find_database(&conn, id)? else {
                return Ok(Some(api_error(StatusCode::NOT_FOUND, "no such database")));
            };

            // Dropping a database destroys data with no undo, so the caller
            // names it — the same rule as removing a domain.
            if confirm.as_deref() != Some(record.name.as_str()) {
                return Ok(Some(api_error(
                    StatusCode::BAD_REQUEST,
                    &format!("confirmation required: send confirm={}", record.name),
                )));
            }

            let engine = database::Engine::parse(&record.engine)?;
            if let Err(err) = database::drop(&cfg, engine, &record.name, &record.db_user) {
                return Ok(Some(api_error(
                    StatusCode::BAD_REQUEST,
                    &format!("{err:#}"),
                )));
            }
            store::delete_database_record(&conn, id)?;

            esw::log_line(&format!(
                "[{}] {actor} dropped database {}",
                daemon::now_secs(),
                record.name
            ));
            api_json(
                StatusCode::OK,
                serde_json::json!({ "removed": record.name }),
            )
        }

        // --- files ---------------------------------------------------------
        // Every path is checked against the domain root inside files.rs; this
        // layer only routes and never joins paths itself.
        (_, r) if r.starts_with("/api/v1/domains/") && r.contains("/files") => {
            let id: i64 = r
                .trim_start_matches("/api/v1/domains/")
                .split('/')
                .next()
                .unwrap_or("")
                .parse()
                .unwrap_or(-1);

            let conn = store::open()?;
            let Some(domain) = store::find_domain(&conn, id)? else {
                return Ok(Some(api_error(StatusCode::NOT_FOUND, "no such domain")));
            };

            let action = r.rsplit('/').next().unwrap_or("");
            let query_path = request
                .uri()
                .query()
                .unwrap_or("")
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(k, _)| *k == "path")
                .map(|(_, v)| percent_decode(v))
                .unwrap_or_else(|| "/".to_string());

            match (method, action) {
                (&Method::GET, "files") => match files::list(&domain, &query_path) {
                    Ok(listing) => api_json(StatusCode::OK, serde_json::json!(listing)),
                    Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
                },

                (&Method::GET, "read") => match files::read(&domain, &query_path) {
                    Ok(content) => api_json(
                        StatusCode::OK,
                        serde_json::json!({ "path": query_path, "content": content }),
                    ),
                    Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
                },

                // Raw bytes, so the browser can save the file as-is.
                (&Method::GET, "download") => match files::read_bytes(&domain, &query_path) {
                    Ok((name, bytes)) => (
                        StatusCode::OK,
                        [
                            (
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("application/octet-stream"),
                            ),
                            (
                                header::CONTENT_DISPOSITION,
                                HeaderValue::from_str(&format!(
                                    "attachment; filename=\"{}\"",
                                    name.replace('"', "")
                                ))
                                .unwrap_or(HeaderValue::from_static("attachment")),
                            ),
                        ],
                        bytes,
                    )
                        .into_response(),
                    Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
                },

                // Multipart is handled here rather than in the panel: the
                // worker cannot parse it, and this keeps file bytes out of the
                // PHP tier entirely instead of buffering them twice.
                (&Method::POST, "upload") => upload(&cfg, &domain, request, actor).await?,

                (&Method::POST, "write") => {
                    let body = json_body(request).await?;
                    let path = field(&body, "path").unwrap_or("").to_string();
                    let content = body.get("content").and_then(|v| v.as_str()).unwrap_or("");
                    match files::write(&cfg, &domain, &path, content) {
                        Ok(saved) => {
                            api_json(StatusCode::OK, serde_json::json!({ "saved": saved }))
                        }
                        Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
                    }
                }

                (&Method::POST, "mkdir") => {
                    let body = json_body(request).await?;
                    let path = field(&body, "path").unwrap_or("").to_string();
                    match files::mkdir(&cfg, &domain, &path) {
                        Ok(made) => {
                            api_json(StatusCode::OK, serde_json::json!({ "created": made }))
                        }
                        Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
                    }
                }

                (&Method::POST, "rename") => {
                    let body = json_body(request).await?;
                    let from = field(&body, "path").unwrap_or("").to_string();
                    let to = field(&body, "to").unwrap_or("").to_string();
                    match files::rename(&cfg, &domain, &from, &to) {
                        Ok(moved) => {
                            api_json(StatusCode::OK, serde_json::json!({ "renamed": moved }))
                        }
                        Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
                    }
                }

                (&Method::DELETE, "files") => match files::delete(&cfg, &domain, &query_path) {
                    Ok(removed) => {
                        esw::log_line(&format!(
                            "[{}] {actor} deleted {} in {}",
                            daemon::now_secs(),
                            removed,
                            domain.name
                        ));
                        api_json(StatusCode::OK, serde_json::json!({ "removed": removed }))
                    }
                    Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
                },

                _ => api_error(StatusCode::NOT_FOUND, "unknown file action"),
            }
        }

        // --- hosting settings ----------------------------------------------
        (_, r) if r.starts_with("/api/v1/domains/") && r.ends_with("/hosting") => {
            let id: i64 = r
                .trim_start_matches("/api/v1/domains/")
                .trim_end_matches("/hosting")
                .trim_matches('/')
                .parse()
                .unwrap_or(-1);

            let conn = store::open()?;
            let Some(domain) = store::find_domain(&conn, id)? else {
                return Ok(Some(api_error(StatusCode::NOT_FOUND, "no such domain")));
            };
            let stored = hosting_of(&domain);

            match *method {
                Method::GET => api_json(
                    StatusCode::OK,
                    serde_json::json!({
                        "settings": stored,
                        "has_certificate": cert::has_certificate(&domain.name),
                        "webserver": domain.webserver,
                        "document_root": domain.docroot,
                    }),
                ),

                Method::POST => {
                    let body = json_body(request).await?;
                    let settings: vhost::HostingSettings = match serde_json::from_value(
                        merge_settings(serde_json::to_value(&stored)?, body.clone()),
                    ) {
                        Ok(settings) => settings,
                        Err(err) => {
                            return Ok(Some(api_error(
                                StatusCode::BAD_REQUEST,
                                &format!("could not read those settings: {err}"),
                            )));
                        }
                    };

                    if let Err(err) = settings.validate() {
                        return Ok(Some(api_error(StatusCode::BAD_REQUEST, &err.to_string())));
                    }

                    // Switching web server is part of hosting rather than a
                    // separate action; the vhost is regenerated either way.
                    if let Some(server) = field(&body, "webserver")
                        && vhost::WebServer::parse(server).is_ok()
                        && server != domain.webserver
                    {
                        let _ = vhost::remove_config(&domain);
                        conn.execute(
                            "UPDATE domains SET webserver = ?2 WHERE id = ?1",
                            rusqlite::params![id, server],
                        )?;
                    }

                    let docroot = settings.docroot_for(&domain.root);
                    let json = serde_json::to_string(&settings)?;
                    let updated = store::update_hosting(&conn, id, &json, &docroot)?;

                    let mut notes = Vec::new();
                    if cfg.mode == config::Mode::Host {
                        // The document root may not exist yet if it was just
                        // pointed somewhere new.
                        if let Err(err) = std::fs::create_dir_all(&docroot) {
                            notes.push(format!("could not create {docroot}: {err}"));
                        }
                        match vhost::write_config(&cfg, &updated, &settings) {
                            Ok(path) => notes.push(format!("vhost written: {}", path.display())),
                            Err(err) => notes.push(format!("vhost not written: {err}")),
                        }
                        if let Ok(server) = vhost::WebServer::parse(&updated.webserver) {
                            notes.push(vhost::reload(server)?);
                        }
                        if let Some(owner) = &updated.customer_username {
                            match vhost::set_shell(&cfg, owner, settings.ssh_access) {
                                Ok(message) => notes.push(message),
                                Err(err) => notes.push(format!("shell unchanged: {err}")),
                            }
                        }
                    } else {
                        notes.push("isolated mode: saved but nothing written".into());
                    }

                    esw::log_line(&format!(
                        "[{}] {actor} changed hosting settings for {}",
                        daemon::now_secs(),
                        updated.name
                    ));
                    api_json(
                        StatusCode::OK,
                        serde_json::json!({ "settings": settings, "notes": notes }),
                    )
                }

                _ => api_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
            }
        }

        // --- php settings --------------------------------------------------
        (_, r) if r.starts_with("/api/v1/domains/") && r.ends_with("/php") => {
            let id: i64 = r
                .trim_start_matches("/api/v1/domains/")
                .trim_end_matches("/php")
                .trim_matches('/')
                .parse()
                .unwrap_or(-1);

            let conn = store::open()?;
            let Some(domain) = store::find_domain(&conn, id)? else {
                return Ok(Some(api_error(StatusCode::NOT_FOUND, "no such domain")));
            };

            let stored: php::PhpSettings = domain
                .php_settings
                .as_deref()
                .and_then(|raw| serde_json::from_str(raw).ok())
                .unwrap_or_default();

            match *method {
                Method::GET => {
                    let version = php::version_for(&domain, &cfg);
                    let installed = esw::installed_versions().unwrap_or_default();

                    // Each installed version with its support state, so the
                    // picker can say which choices are already unsupported
                    // rather than listing them all as equivalent.
                    let versions: Vec<serde_json::Value> = installed
                        .iter()
                        .map(|candidate| {
                            let (eol, date) =
                                system::engine_end_of_life(candidate).unwrap_or((false, "unknown"));
                            serde_json::json!({
                                "version": candidate,
                                "end_of_life": eol,
                                "end_of_life_date": date,
                            })
                        })
                        .collect();

                    let (eol, eol_date) =
                        system::engine_end_of_life(&version).unwrap_or((false, "unknown"));

                    api_json(
                        StatusCode::OK,
                        serde_json::json!({
                            "settings": stored,
                            "version": version,
                            "end_of_life": eol,
                            "end_of_life_date": eol_date,
                            "available_versions": versions,
                            "suggested_disable_functions": php::SUGGESTED_DISABLED,
                            "pool_socket": php::socket_path(&domain.name)?.to_string_lossy(),
                        }),
                    )
                }

                Method::POST => {
                    let body = json_body(request).await?;

                    // Merged onto what is stored, so a form posting a subset
                    // cannot silently reset everything it did not mention.
                    let settings: php::PhpSettings = match serde_json::from_value(merge_settings(
                        serde_json::to_value(&stored)?,
                        body.clone(),
                    )) {
                        Ok(settings) => settings,
                        Err(err) => {
                            return Ok(Some(api_error(
                                StatusCode::BAD_REQUEST,
                                &format!("could not read those settings: {err}"),
                            )));
                        }
                    };

                    if let Err(err) = settings.validate() {
                        return Ok(Some(api_error(StatusCode::BAD_REQUEST, &err.to_string())));
                    }

                    let version = field(&body, "version")
                        .map(str::to_string)
                        .filter(|v| !v.is_empty());
                    if let Some(version) = &version
                        && !esw::is_installed(version)
                    {
                        return Ok(Some(api_error(
                            StatusCode::BAD_REQUEST,
                            &format!("PHP {version} is not installed"),
                        )));
                    }

                    let json = serde_json::to_string(&settings)?;
                    let updated = store::update_php(&conn, id, version.as_deref(), &json)?;

                    // Written before applying: if the pool fails to reload, the
                    // stored settings still match what was asked for, and the
                    // message says what happened.
                    let applied = match php::apply(&cfg, &updated, &settings) {
                        Ok(message) => message,
                        Err(err) => format!("saved, but not applied: {err:#}"),
                    };

                    esw::log_line(&format!(
                        "[{}] {actor} changed PHP settings for {}",
                        daemon::now_secs(),
                        updated.name
                    ));
                    api_json(
                        StatusCode::OK,
                        serde_json::json!({ "settings": settings, "result": applied }),
                    )
                }

                _ => api_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
            }
        }

        // --- certificates --------------------------------------------------
        (&Method::GET, r) if r.starts_with("/api/v1/domains/") && r.ends_with("/certificate") => {
            let id: i64 = r
                .trim_start_matches("/api/v1/domains/")
                .trim_end_matches("/certificate")
                .trim_matches('/')
                .parse()
                .unwrap_or(-1);
            let conn = store::open()?;
            match store::find_domain(&conn, id)? {
                Some(domain) => api_json(
                    StatusCode::OK,
                    serde_json::json!({
                        "certificate": cert::status(&domain.name),
                        "certbot_installed": cert::certbot_available(),
                        "auto_renewal": cert::renewal_timer_active(),
                    }),
                ),
                None => api_error(StatusCode::NOT_FOUND, "no such domain"),
            }
        }

        (&Method::POST, r) if r.starts_with("/api/v1/domains/") && r.ends_with("/certificate") => {
            let id: i64 = r
                .trim_start_matches("/api/v1/domains/")
                .trim_end_matches("/certificate")
                .trim_matches('/')
                .parse()
                .unwrap_or(-1);
            let body = json_body(request).await?;
            let staging = body
                .get("staging")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let conn = store::open()?;
            let Some(domain) = store::find_domain(&conn, id)? else {
                return Ok(Some(api_error(StatusCode::NOT_FOUND, "no such domain")));
            };

            // Prefer the customer's address so expiry notices reach whoever
            // owns the site rather than the operator.
            let email = field(&body, "email").map(str::to_string).or_else(|| {
                store::find_customer(&conn, domain.customer_id)
                    .ok()
                    .flatten()
                    .and_then(|c| c.email)
            });

            match cert::issue(&cfg, &domain, email.as_deref(), staging) {
                Ok(output) => {
                    // The vhost has to be rewritten: it only gains its TLS
                    // block once the certificate is actually on disk.
                    let mut notes = vec![];
                    match vhost::write_config(&cfg, &domain, &hosting_of(&domain)) {
                        Ok(path) => notes.push(format!("vhost rewritten: {}", path.display())),
                        Err(err) => notes.push(format!("vhost not rewritten: {err}")),
                    }
                    if let Ok(server) = vhost::WebServer::parse(&domain.webserver) {
                        notes.push(vhost::reload(server)?);
                    }
                    match cert::install_renewal_hook(&cfg) {
                        Ok(path) => notes.push(format!("renewal hook: {}", path.display())),
                        Err(err) => notes.push(format!("renewal hook not installed: {err}")),
                    }
                    esw::log_line(&format!(
                        "[{}] {actor} issued a certificate for {}",
                        daemon::now_secs(),
                        domain.name
                    ));
                    api_json(
                        StatusCode::OK,
                        serde_json::json!({
                            "certificate": cert::status(&domain.name),
                            "notes": notes,
                            "certbot": output.lines().rev().take(6).collect::<Vec<_>>(),
                        }),
                    )
                }
                Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
            }
        }

        (&Method::DELETE, r)
            if r.starts_with("/api/v1/domains/") && r.ends_with("/certificate") =>
        {
            let id: i64 = r
                .trim_start_matches("/api/v1/domains/")
                .trim_end_matches("/certificate")
                .trim_matches('/')
                .parse()
                .unwrap_or(-1);
            let conn = store::open()?;
            let Some(domain) = store::find_domain(&conn, id)? else {
                return Ok(Some(api_error(StatusCode::NOT_FOUND, "no such domain")));
            };
            let output = cert::remove(&cfg, &domain.name)?;
            // Back to plain HTTP, or nginx would reference files that are gone.
            let _ = vhost::write_config(&cfg, &domain, &hosting_of(&domain));
            if let Ok(server) = vhost::WebServer::parse(&domain.webserver) {
                let _ = vhost::reload(server);
            }
            api_json(
                StatusCode::OK,
                serde_json::json!({ "removed": domain.name, "certbot": output }),
            )
        }

        (&Method::POST, "/api/v1/certificates/renew") => {
            let body = json_body(request).await?;
            let force = body.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
            match cert::renew_all(&cfg, force) {
                Ok(output) => api_json(
                    StatusCode::OK,
                    serde_json::json!({ "output": output.lines().collect::<Vec<_>>() }),
                ),
                Err(err) => api_error(StatusCode::BAD_REQUEST, &format!("{err:#}")),
            }
        }

        (&Method::DELETE, r) if path_id(r, "/api/v1/domains").is_some() => {
            let id = path_id(r, "/api/v1/domains").unwrap();

            // Read the confirmation before touching anything. Accepted from the
            // query string or a JSON body so both a browser form and a script
            // can supply it.
            let query_confirm = request
                .uri()
                .query()
                .unwrap_or("")
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(k, _)| *k == "confirm")
                .map(|(_, v)| percent_decode(v));
            let body = json_body(request).await.unwrap_or(serde_json::json!({}));
            let confirm = query_confirm.or_else(|| field(&body, "confirm").map(str::to_string));

            let conn = store::open()?;
            let domain = match store::find_domain(&conn, id)? {
                Some(domain) => domain,
                None => return Ok(Some(api_error(StatusCode::NOT_FOUND, "no such domain"))),
            };

            // This deletes a directory tree and revokes a live site, so the
            // caller must name what they are destroying. Enforced here rather
            // than only in the UI: a client-side prompt guards nothing.
            if confirm.as_deref() != Some(domain.name.as_str()) {
                return Ok(Some(api_error(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        "confirmation required: send confirm={} to remove this domain and its files",
                        domain.name
                    ),
                )));
            }

            let mut notes = Vec::new();
            if cfg.mode == config::Mode::Host {
                let _ = php::remove(&cfg, &domain);
                let _ = vhost::remove_config(&domain);
                match vhost::deprovision(&cfg, &domain) {
                    Ok(()) => notes.push(format!("removed {}", domain.root)),
                    Err(err) => notes.push(format!("files kept: {err}")),
                }
                if let Ok(server) = vhost::WebServer::parse(&domain.webserver) {
                    notes.push(vhost::reload(server)?);
                }
            }

            store::delete_domain(&conn, id)?;
            esw::log_line(&format!(
                "[{}] {actor} removed domain {}",
                daemon::now_secs(),
                domain.name
            ));
            api_json(
                StatusCode::OK,
                serde_json::json!({ "removed": domain.name, "notes": notes }),
            )
        }

        _ => return Ok(None),
    };

    Ok(Some(response))
}

fn unauthenticated_response() -> Response {
    redirect("/login")
}

fn redirect(location: &str) -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .body(Body::empty())
        .expect("static redirect is always valid")
}

fn html(status: StatusCode, body: String) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

async fn serve_static(path: &std::path::Path) -> Result<Response> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("could not read {}", path.display()))?;
    let mime = mime_for(path);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, HeaderValue::from_static(mime))],
        bytes,
    )
        .into_response())
}

/// Build the CGI environment and hand the request to php-fpm.
async fn forward_to_php(
    inner: &Inner,
    request: Request,
    script_path: &std::path::Path,
    script_name: &str,
    document_uri: &str,
    user: &str,
) -> Result<Response> {
    let (parts, body) = request.into_parts();
    let query = parts.uri.query().unwrap_or("").to_string();
    let request_uri = match parts.uri.path_and_query() {
        Some(pq) => pq.as_str().to_string(),
        None => document_uri.to_string(),
    };

    let body_bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .context("request body too large or unreadable")?;

    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let script_filename = script_path.to_string_lossy().to_string();
    let document_root = inner.public_dir.to_string_lossy().to_string();
    let method = parts.method.as_str().to_string();

    let mut params = Params::default()
        .gateway_interface("CGI/1.1")
        .server_software(concat!("ember/", env!("CARGO_PKG_VERSION")))
        .server_protocol("HTTP/1.1")
        .request_method(method)
        .script_filename(script_filename)
        .script_name(script_name.to_string())
        .document_uri(document_uri.to_string())
        .document_root(document_root)
        .request_uri(request_uri)
        .query_string(query)
        .server_name(inner.host.clone())
        .server_addr(inner.host.clone())
        .server_port(inner.port)
        .remote_addr("127.0.0.1")
        .remote_port(0)
        .content_type(content_type)
        .content_length(body_bytes.len());

    // Everything else the app might read arrives as HTTP_*. A client must not
    // be able to forge identity, so its own REMOTE_USER header is dropped.
    for (name, value) in parts.headers.iter() {
        let Ok(value) = value.to_str() else { continue };
        let key = format!("HTTP_{}", name.as_str().to_uppercase().replace('-', "_"));
        if key == "HTTP_REMOTE_USER" {
            continue;
        }
        params = params.custom(key, value.to_string());
    }

    // The authenticated system account. Symfony's `remote_user` authenticator
    // reads exactly this, so the firewall needs no custom code.
    params = params
        .custom("REMOTE_USER", user.to_string())
        .custom("EMBER_USER", user.to_string())
        .custom("AUTH_TYPE", "ember-session");

    // The pool listens on a unix socket normally, loopback TCP when the socket
    // path would exceed the platform limit. Both speak the same protocol.
    let response = match &inner.pool {
        PoolAddr::Unix(path) => {
            let stream = tokio::net::UnixStream::connect(path)
                .await
                .with_context(|| format!("could not reach esw-engine at {}", path.display()))?;
            execute(stream, params, body_bytes.to_vec()).await
        }
        PoolAddr::Tcp(addr) => {
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .with_context(|| format!("could not reach esw-engine at {addr}"))?;
            execute(stream, params, body_bytes.to_vec()).await
        }
    }?;

    if let Some(stderr) = response.stderr.as_ref().filter(|s| !s.is_empty()) {
        esw::log_line(&format!(
            "esw-engine: {}",
            String::from_utf8_lossy(stderr).trim()
        ));
    }

    build_response(response.stdout.unwrap_or_default())
}

/// Run one FastCGI exchange over whichever transport the pool is using.
async fn execute<S>(
    stream: S,
    params: Params<'_>,
    body: Vec<u8>,
) -> Result<fastcgi_client::Response>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    Client::new_tokio(stream)
        .execute_once(FcgiRequest::new_tokio(params, std::io::Cursor::new(body)))
        .await
        .context("esw-engine request failed")
}

/// FastCGI returns a CGI document: headers, blank line, body.
fn build_response(stdout: Vec<u8>) -> Result<Response> {
    let split = find_subslice(&stdout, b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| find_subslice(&stdout, b"\n\n").map(|i| (i, 2)));

    let (head, body) = match split {
        Some((idx, len)) => (&stdout[..idx], stdout[idx + len..].to_vec()),
        // No header block at all — treat the whole thing as the body so PHP
        // fatal errors are still visible instead of vanishing.
        None => (&[][..], stdout.clone()),
    };

    let mut builder = Response::builder();
    let mut status = StatusCode::OK;

    for line in String::from_utf8_lossy(head).lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());

        if name.eq_ignore_ascii_case("Status") {
            if let Some(code) = value.split_whitespace().next()
                && let Ok(parsed) = code.parse::<u16>()
                && let Ok(parsed) = StatusCode::from_u16(parsed)
            {
                status = parsed;
            }
            continue;
        }

        if let (Ok(name), Ok(value)) = (
            HeaderName::try_from(name.to_ascii_lowercase()),
            HeaderValue::from_str(value),
        ) {
            builder = builder.header(name, value);
        }
    }

    builder
        .status(status)
        .body(Body::from(body))
        .context("could not build response from php-fpm output")
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Minimal `%XX` decoding — enough for static paths, no dependency needed.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn mime_for(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        "map" => "application/json",
        _ => "application/octet-stream",
    }
}
