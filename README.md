# Ember

A server control panel for Linux servers.

> [!WARNING]
> **Work in progress.** Ember is being built in the open and is not ready to run
> anything you care about. It handles system accounts and passwords, and that
> code has not been audited or run in anger. Expect breaking changes, missing
> pieces, and sharp edges. Read [what is not done yet](#notes-on-what-is-not-done-yet)
> before going near a real server.

## Why this exists

Another subscription went up in price, and I did not feel like paying it. So:
an admin panel.

That is the whole motivation. It also explains some of the choices — Ember is
meant to be something you install on your own server and own outright, not
something you rent. One binary, no control plane phoning home, no seat count.

## What it is

Ember is a single Rust binary that **is** the service. It supervises its own
execution engine, terminates HTTP itself, authenticates against real system
accounts, and serves a Symfony panel from resident workers.

The login and setup screens are rendered by Rust, not the panel — authentication
lives where the PAM stack and the signing key are. Everything past the session
cookie is Symfony's.

```
┌─ ember (rust) ────────────────────────────────────────┐
│  • HTTP server            terminates :7878            │
│  • auth                   system users, signed cookie │
│  • control API            /api/v1/*  (privileged)     │
│  • supervisor ────────────┐                           │
└───────────────────────────┼───────────────────────────┘
                            │ FastCGI
                   ┌────────▼──────────┐
                   │  esw-engine       │  pinned, ember-owned
                   │  (panel pool)     │  ~/.ember/esw/<version>/
                   └────────┬──────────┘
                            │
                   ┌────────▼──────────┐
                   │  Symfony 8 panel  │  ~/.ember/panel/
                   │  remote_user auth │  public/index.php
                   └───────────────────┘

/usr/bin/php  ← never read, written, or executed
```

## esw-engine

The **Ember Service Worker engine** is what executes the panel. It is a pinned
static build that Ember downloads into its own tree, with its own ini and its
own pool config.

It is deliberately never called "PHP" in anything a customer sees — customers
choose PHP versions for *their own sites*, and those are entirely separate
pools. Conflating the two is exactly the confusion this naming avoids.

The panel pool is simply the first pool Ember supervises; per-site pools reuse
the same machinery, each with its own version and its own system user.

## Install on a server

```console
curl -fsSL https://raw.githubusercontent.com/KumaVolt/ember/main/install.sh | sudo sh
```

> [!NOTE]
> This works today for everything except the binary, which needs a published
> release. Until one is tagged, build it and point the installer at it:
>
> ```console
> cargo build --release
> sudo EMBER_BINARY_URL=file://$PWD/target/release/ember \
>      EMBER_PANEL_SRC=$PWD/panel \
>      sh install.sh
> ```
>
> Or run the container, which takes the same path:
> `docker build -t ember . && docker run -d -p 7878:7878 -v ember-state:/var/lib/ember ember`

The installer puts the binary in place, writes `/etc/pam.d/ember`, provisions
esw-engine, creates the unprivileged `ember-esw` account, deploys the panel and
resolves its Composer dependencies, generates a unique `APP_SECRET`, installs a
systemd unit with `EMBER_MODE=host`, starts it, and prints the URL to open.
Visit that URL — the first page is setup.

**The server needs no PHP and no Composer of its own.** `install.sh` runs
Composer through `ember esw php`, the command-line half of the same pinned build
that serves the panel — so what compiles the panel is exactly what runs it.

**The panel comes from this repository**, not a release asset: the installer
pulls the branch (or tag) archive and uses `panel/` from it.

**The container runs this same script.** The Dockerfile compiles the binary and
then calls `install.sh` in build mode (`EMBER_SKIP_SERVICE=1`); it does not
reimplement any setup step. One code path, so a container and a real install
cannot drift apart.

| Variable | Purpose | Default |
| --- | --- | --- |
| `EMBER_REPO` | Repository to install from | `KumaVolt/ember` |
| `EMBER_VERSION` | Release tag, or `latest` | `latest` |
| `EMBER_BRANCH` | Branch used for the panel when untagged | `main` |
| `EMBER_BINARY_URL` | Install a specific binary | — |
| `EMBER_PANEL_SRC` | Deploy the panel from a local directory | — |
| `EMBER_SKIP_SERVICE` | Install everything, start nothing | — |

## Authentication

Panel users **are** system users. There is no parallel user directory.

**First run** redirects everything to `/setup`: pick a username (default `admin`),
a password of at least 12 characters, and optionally an email. Once an
administrator exists, `/setup` is closed permanently.

**Signing in** happens at `/login` with a username and password. Passwords are
checked by **PAM** against the real system account — so `passwd`, account expiry,
and account locking all apply, with no password copy kept by Ember.

There are two identity sources, and the distinction matters:

| Source | Password lives | Used for |
| --- | --- | --- |
| `system` | The system database, checked via PAM | Every real panel user |
| `local` | An Argon2 hash in `$EMBER_HOME/accounts.json` | **Setup and recovery only** |

A `local` account exists so the panel can be bootstrapped and recovered — notably
in isolated mode, where Ember will not create a system account at all. It is not
a general user system.

**Recovery**, when you are locked out:

```console
$ ember recover
New password: ...
```

Running it requires being on the machine — the same proof of possession that
`ember login` relies on.

**`ember login`** still issues a single-use URL that skips the form, for when
you are already on the server and would rather not type a password:

```console
$ ember login
one-time login URL for system user "root":

  http://127.0.0.1:7878/login?token=5a462526f37f317640d419d5…

valid once, expires in 180 seconds.
```

Once signed in, Ember passes the account to the panel as `REMOTE_USER` — exactly
what Symfony's built-in `remote_user` authenticator reads, so the firewall needs
no custom code:

```yaml
# config/packages/security.yaml — as deployed
security:
    providers:
        ember_users:
            id: App\Security\EmberUserProvider
    firewalls:
        main:
            pattern: ^/
            provider: ember_users
            stateless: true      # Ember owns the session, not Symfony
            remote_user:
                provider: ember_users
    access_control:
        - { path: ^/, roles: ROLE_USER }
```

`App\Security\EmberUserProvider` turns the identity into a Symfony user without
consulting any user table — Ember is the authority, and it strips any
client-supplied `Remote-User` header, so what arrives is trustworthy.

Properties worth stating explicitly, all verified:

- Login tokens are **single use**; a replay is rejected.
- Tokens are stored **hashed**, so a readable token file cannot be replayed.
- A client-supplied `Remote-User` header is **stripped** — identity cannot be
  forged from outside.
- Wrong password and unknown user return an **identical** message, so the form
  cannot enumerate usernames.
- **Five failed attempts** locks an account for 15 minutes.
- A broken PAM stack reports as a server error, never as "wrong password".
- Deleting an account **revokes its live sessions** — identity is rechecked per
  request.
- The signing key lives in `$EMBER_HOME/secret.key`, mode `0600`;
  `accounts.json` is `0600` too.

## Isolated mode

Ember will not modify the machine it runs on unless you explicitly say so.

| Mode | Meaning |
| --- | --- |
| `isolated` *(default)* | Manages nothing outside `$EMBER_HOME`. Reads the system user database — that is how login works — but never writes to it. Setup creates a `local` administrator instead of a system account. |
| `host` | May create system accounts and manage services on the machine it runs on. |

Set with `EMBER_MODE`, or `mode` in `config.json`. The container sets
`EMBER_MODE=host`, because inside the container the container *is* the machine
being managed. On a laptop the default holds:

```console
$ ember users create alice
Error: refusing to create system user "alice": ember is in isolated mode and
will not modify this machine.
run with EMBER_MODE=host (or use the container) if that is genuinely what you want.
```

The check lives **inside** `create_system_user` and `set_system_password` — the
functions that actually shell out to `useradd` and `chpasswd` — not merely at
their call sites. A caller cannot forget it, so "it won't touch my laptop" is a
property of the code rather than a habit.

## The control API

The panel runs unprivileged and cannot create system users or manage services
on its own. Anything privileged is delegated to Ember over `/api/v1/*`, which is
served by Rust and reserved before the filesystem is consulted — a file dropped
in `public/api/` can never shadow it.

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Liveness. The only unauthenticated route besides `/login`. |
| `GET /api/v1/status` | Service state, engine version, pool address. |
| `GET /api/v1/whoami` | The authenticated system account. |
| `GET /api/v1/users` | System accounts that can log into the panel. Read-only — creating one is a mutation and goes through the host-mode gate. |

## Commands

```console
$ ember esw install          # provision the engine (worker + CLI)
$ ember esw which            # where those binaries live
$ ember esw php -- -v        # run ember's own PHP
$ ember start                # detach and serve
$ ember start --foreground   # stay in this terminal
$ ember status [--json]
$ ember login [--user NAME]
$ ember users list [--json]
$ ember users create NAME    # host mode + root only
$ ember recover [--user X]   # restore access when locked out
$ ember logs [-n 40]
$ ember stop
$ ember restart
```

## Configuration

Precedence: **CLI flag → environment → `$EMBER_HOME/config.json` → default.**

| Setting | Flag | Environment | Default |
| --- | --- | --- | --- |
| Port | `--port` | `EMBER_PORT` | `7878` |
| Bind address | `--host` | `EMBER_HOST` | `127.0.0.1` |
| Engine version | — | `EMBER_ESW_VERSION` | `8.4.23` |
| State directory | — | `EMBER_HOME` | `~/.ember` |
| Engine directory | — | `EMBER_ESW_DIR` | `$EMBER_HOME/esw` |
| Public URL | — | `EMBER_PUBLIC_URL` | derived from bind address |
| Mode | — | `EMBER_MODE` | `isolated` |
| Pool account | — | `EMBER_ESW_USER` | `nobody` (root runs only) |
| PAM service | — | `EMBER_PAM_SERVICE` | `chkpasswd` on macOS, `ember` on Linux |
| Worker count | — | `EMBER_WORKERS` | 2–4, by core count |

The port is still a **placeholder** pending a decision. Changing it is a flag,
an env var, or one constant in `src/config.rs` — never a refactor.

## Layout

```
$EMBER_HOME/
├── esw/8.4.23/sbin/php-fpm   the worker that serves the panel
├── esw/8.4.23/bin/php        the matching CLI, for composer and bin/console
├── conf/esw.ini              generated; rewritten on every start
├── conf/esw-pool.conf        generated; the panel pool
├── run/esw.sock              engine socket
├── log/ember.log             service log
├── log/esw.log               engine log
├── panel/                    the Symfony app (public/index.php is its front controller)
├── accounts.json             panel accounts (setup + recovery), 0600
├── secret.key                session signing key, 0600
└── ember.json                written only once actually serving
```

## Container

One container, one process tree: `ember` is PID 1 and supervises esw-engine as
its child. No nginx, no supervisord, no sidecar.

```console
$ docker build -t ember:dev .
$ docker run -d --name ember -p 7878:7878 -v ember-state:/var/lib/ember ember:dev
$ docker exec ember ember login
```

The engine is baked into the image at `/opt/ember/esw`, kept separate from state
at `/var/lib/ember` so mounting a volume for state does not mask it.

`docker stop` sends SIGTERM to Ember, which drains in-flight requests and asks
the engine to finish its work before exiting.

> A control panel can only manage what it can see. In a container Ember manages
> the container, not your host — that is the point of shipping it this way.

**Panel users are system users, and in a container they live in the container's
`/etc/passwd` and `/etc/shadow`.** Those are in the writable layer, so replacing
the container to ship an update discards every panel account. If accounts must
survive an image update, persist the user database and home directories on the
volume too.

## Worker mode

The panel does not run under request-per-process FPM. Ember keeps a pool of
**resident Symfony workers**: the kernel boots once and then serves request
after request, so the steady-state cost is routing and the controller, not a
framework bootstrap.

```
ember (rust) :7878
   │  one request at a time per worker, over stdin/stdout pipes
   ▼
esw worker × N   ← Symfony kernel booted ONCE, resident
```

Measured on this panel, 200 requests over one keep-alive connection:

| Mode | Per request |
| --- | --- |
| worker | **0.61 ms** |
| fastcgi | 1.46 ms |

2.4× on an app with one controller and no database — the gap widens as the
service container grows, because what is being removed is the bootstrap.

Worker mode engages when the panel ships `bin/esw-worker.php`. Without it Ember
falls back to FastCGI, which is what the placeholder front controller needs. The
fallback is logged loudly: it is a large silent slowdown otherwise.

Being resident brings obligations that FPM handled for free:

- **Per-request state is reset** via Symfony's `ServicesResetter`, exposed as
  `esw.services_resetter` (Symfony keeps it private). Without it, request-scoped
  services would leak between unrelated requests.
- **Workers are recycled** after 500 requests, the same reasoning as FPM's
  `pm.max_requests` — a resident process accumulates whatever the app leaks.
- **A worker that errors is destroyed, not reused**, since a protocol failure
  leaves the pipe in an unknown state.
- **stdout is protocol-only.** Response output is buffered and diagnostics go to
  stderr, which Ember relays into its log; a stray `echo` would corrupt framing.
- Requests are capped at 120s, after which the worker is replaced.

Pool size is `EMBER_WORKERS`, defaulting to 2–4 by core count.

## Settings

```
Settings
├── Server management
│   ├── Server statistics    load, memory, swap, disks, uptime
│   ├── Server updates       this server's packages, and Ember itself
│   ├── Restart server
│   └── Shut down server
├── Services                 install PHP versions, databases, web servers
└── Appearance               branding, languages
```

**Services** is a catalogue of components with their real state — installed,
running, version — and installation through the distribution's package manager:
MariaDB, PostgreSQL, Redis, nginx, Apache, certbot, plus extra PHP versions for
customer sites. Where Ember can install something but cannot yet *use* it —
PostgreSQL and Redis — the entry says so rather than implying more than exists.

Nothing is removed from here. Uninstalling a database server out from under a
customer's site is not worth putting behind one click.

**Restart and shut down** are the most destructive actions in the product, so
they require typing the machine's hostname, and are refused outright in isolated
mode. Naming the machine is the point: an operator with several panels open
should not be able to take down the wrong one from the wrong tab.

Statistics come from `/proc` and `statvfs` directly rather than parsing `top` or
`df`. On a machine without `/proc` the fields are simply absent rather than
guessed.

Update checking reaches GitHub and the package manager only when the page is
opened — a panel that phones home on its own is what this is meant to avoid.
Ember reports what the package manager says but does not apply system updates:
an unattended upgrade of a database or web server is not something to do behind
a button.

## Theming and white-labelling

The panel ships a light theme with a blue accent, built on design tokens rather
than colour literals — every colour resolves through a CSS custom property, so a
theme is an override of one block.

Branding is configuration, not a template edit, and both tiers read the same
source: the Rust-rendered sign-in page and the Symfony panel stay in step.

```console
$ EMBER_BRAND_NAME="Nimbus Hosting" \
  EMBER_BRAND_ACCENT="#7c3aed" \
  EMBER_BRAND_TAGLINE="Managed hosting control" ember start
```

Editable from **Settings → Appearance**, which writes to `config.json` and
leaves every other setting in it alone. Values pinned by environment variables
are shown as such rather than silently failing to save.

Or set it directly in `$EMBER_HOME/config.json`:

```json
{ "branding": { "name": "Nimbus Hosting", "accent": "#7c3aed", "logo_url": "/logo.svg" } }
```

The accent is validated before it reaches the stylesheet, so a value from config
cannot break out of the style block.

## Customers and domains

A customer **is** a system account. A domain belongs to a customer, and its
files are owned by that customer's user and group — which is the isolation
boundary, not a convention.

```text
/var/www/vhosts/<domain>/
  webroot/      the document root — the only directory served
  private/      never served: application storage, credentials, uploads
  logs/         access.log and error.log for this domain alone
  conf/         the generated vhost config
  error_docs/   403, 404 and 500 pages, wired into the vhost
  cgi-bin/      CGI scripts, deliberately outside the document root
  tmp/          per-domain scratch, off the shared /tmp
```

The split between `webroot` and `private` is the point: only `webroot` is
reachable by URL, so anything a site must keep but must not expose has an
obvious home that no request can reach.

`webroot/index.html` is a branded default page carrying the operator's name and
accent, marked `noindex`. It tells the customer the domain is working and how to
replace it, so a new domain never answers with the web server's stock page — and
neither do its errors.

Creating a domain writes that tree, chowns it to the customer, generates an
nginx or apache vhost pointing PHP at a pool that runs as that customer, and
reloads the web server. In isolated mode none of it is written and the API says
so rather than pretending.

**Ember serves the panel itself and never delegates that to nginx.** These
vhosts are for customer domains only.

| Endpoint | Purpose |
| --- | --- |
| `GET/POST /api/v1/customers` | List and create; creating also makes the system account |
| `DELETE /api/v1/customers/{id}` | Refuses while domains still reference it |
| `GET/POST /api/v1/domains` | List and create; creating provisions files and vhost |
| `DELETE /api/v1/domains/{id}` | Removes the vhost and the directory tree |
| `GET /api/v1/summary` | Counts for the dashboard |
| `GET /api/v1/branding` | White-label settings |

Mutations require an administrator. Reads work for any signed-in account, so the
panel renders without elevated rights.

## TLS certificates

Certificates come from Let's Encrypt via **certbot**, driven by Ember. Issuance
has a lot of hard-won edge cases — rate limits, account recovery, revocation, CA
policy changes — and certbot has absorbed all of them, so Ember configures it
rather than reimplementing ACME.

```console
$ ember cert issue example.com --email ops@example.com
$ ember cert list
$ ember cert renew [--force]
```

Or from the panel: **Enable SSL** on the domain row. The panel runs nothing
itself — it calls `POST /api/v1/domains/{id}/certificate`, and Ember does the
privileged work. PHP never touches certbot or `/etc/letsencrypt`.

Validation is HTTP-01 over the domain's own webroot, so nothing stops and no
port is taken over. Two details matter and are easy to get wrong:

- **The challenge path is exempted in the vhost.** The generated config denies
  dotfiles, which would 403 `/.well-known/acme-challenge/` and break issuance —
  and, worse, break *renewal* silently once TLS is on. Nginx matches it with
  `location ^~` so it wins against the dotfile rule; apache aliases it and the
  HTTPS redirect explicitly skips it.
- **Renewal reloads the web server.** Certbot rewrites the files on its own
  timer, but a running server holds the old certificate open until told to
  reload. `install.sh` writes `/etc/letsencrypt/renewal-hooks/deploy/ember-reload`
  so a renewed certificate is actually served.

Once a certificate exists the vhost is regenerated: port 80 becomes a redirect
(except the challenge path), and the site moves to 443 with TLS 1.2+.

`ember cert list` reports whether renewal is actually scheduled — via
`certbot.timer` or the cron entry. A certificate that quietly stops renewing is
invisible until the day it expires, so it is stated rather than assumed.

Use `--staging` while DNS is still settling: untrusted certificates, far looser
rate limits.

## Databases

One MariaDB server hosts every customer's databases. **Isolation is the
server's own grant system, not filtering in the panel** — a user is granted
rights on exactly one database and cannot see any other in `SHOW DATABASES`. The
boundary therefore holds for a customer connecting directly with a MySQL client,
not only for one going through the panel.

Verified on a live server with two customers:

| Connected as | Sees |
| --- | --- |
| `root` | every database |
| `acme_wordpress` | `acme_wordpress`, `information_schema` |
| `globex_wordpress` | `globex_wordpress`, `information_schema` |

Reaching across fails with `ERROR 1044 Access denied`, and so does reading
`mysql.user`. `GET /api/v1/databases/{id}/grants` asks the server what a user can
actually reach, rather than the panel asserting it.

Names are prefixed with the owner, so `wordpress` becomes `acme_wordpress` and
two customers can both use the name they want.

Passwords are generated, shown **once**, and never stored — there is no way to
display one again, only to reset it. Dropping a database destroys data with no
undo, so it requires typing the database name, enforced in the API.

Ember drives the `mysql` client rather than linking a driver, for the same
reason it drives certbot. Statements go in over **stdin**, never as arguments,
so a password never appears in the process list. Identifiers are restricted to a
closed character set rather than escaped — quoting arbitrary strings into SQL is
a defence that has failed for enough other people to be worth not relying on.

PostgreSQL and Redis are recognised by the engine type and refused with a clear
message; the shape is there so adding them does not mean reworking the store or
the API.

## File manager

Each domain gets a browser for its own directory: navigate, edit text files,
create, rename, delete, and download. Reached from the **Files** tool on a
domain row.

Containment is the whole job here, since every path comes from a browser. A
resolved path must live under the domain root or the operation is refused, and
three escapes are closed:

- `..` and absolute paths are rejected before anything touches the disk.
- The result is **canonicalised**, which resolves symlinks — so a link planted
  inside `webroot` pointing at `/etc` resolves outside the root and fails.
- Paths that do not exist yet have their **parent** canonicalised instead, so a
  new file cannot be created through a link either.

All of it is enforced in Rust. The panel never joins a path or touches the
filesystem; it passes the operator's input to the control API and renders the
answer. Files the panel writes are chowned to the customer, because a panel that
leaves root-owned files in a customer's tree breaks their own site.

Verified against a live container: traversal refused, reads *and* writes through
a planted `/etc` symlink refused, and the domain root itself cannot be deleted.

Binary files and anything over 2 MB are download-only rather than opened in the
editor.

**Uploads post straight to the control API**, not through the panel. The worker
cannot parse multipart, and this keeps file bytes out of the PHP tier entirely
instead of buffering them twice. An uploaded name is reduced to its final
component before use, so a filename can never steer the path — verified with
`../../../../etc/pwned.txt`, which lands as `webroot/pwned.txt`. The
post-upload redirect is confined to same-origin paths.

## The panel

`panel/` in this repository is a Symfony 8.1 application. Its source is version
controlled; `vendor/` and `var/` are build artefacts, resolved on the target by
`install.sh` using Ember's own PHP.

It authenticates through Symfony's built-in `remote_user` firewall — no custom
authenticator — and calls Ember's control API for anything it cannot see itself,
such as the engine version and pool address.

```
panel/bin/esw-worker.php                   the resident worker loop
panel/src/Security/EmberUserProvider.php   REMOTE_USER -> Symfony user
panel/src/Security/EmberUser.php           identity + roles, no credential
panel/config/packages/security.yaml        stateless remote_user firewall
panel/config/services.yaml                 public alias for the resetter
```

If no panel is deployed, Ember writes a small placeholder `public/index.php` so
the panel still answers. Swapping frameworks means replacing that directory —
Ember serves whatever `public/index.php` it finds and needs no Rust changes.

## Notes on what is not done yet

- **No published release yet.** The installer fetches the panel from this
  repository, but the binary comes from a GitHub release, and none is tagged.
  Until one is, pass `EMBER_BINARY_URL` pointing at a local build. Tagging
  `v*` runs `.github/workflows/release.yml`, which builds and publishes the
  x86_64 and aarch64 binaries the installer expects.
- **Customers, domains, and vhosts are not built.** The plan is customers mapped
  to system accounts, each owning domains, each domain getting its own nginx or
  apache vhost under `/var/www/vhosts/<domain>` scoped by user and group. None of
  that exists yet.
- **CSRF on the login form.** Mitigated by `SameSite=Lax` today, but a real
  token is the correct fix.
- **TLS for the panel itself.** Customer domains can get certificates, but the
  panel still serves plain HTTP on its own port, so its session cookie is
  `HttpOnly` + `SameSite=Lax` and not yet `Secure`.
- **Successful issuance is untested.** The path to certbot is verified end to
  end — including a real rejection from Let's Encrypt staging — but obtaining an
  actual certificate needs a public domain pointing at the server.
- **Per-site pools.** The machinery is shaped for them; only the panel pool
  exists today.
- **No published release yet.** `https://get.ember.sh` does not exist; the
  installer needs `EMBER_BINARY_URL` and `EMBER_PANEL_SRC` until there is one.
- **The systemd path is unverified.** The unit passes `systemd-analyze verify`,
  but containers do not run systemd, so only the non-systemd fallback has been
  executed end to end.
