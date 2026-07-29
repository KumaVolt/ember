#!/bin/sh
# Ember installer — set up the control panel on a fresh server.
#
#   curl -fsSL https://raw.githubusercontent.com/KumaVolt/ember/main/install.sh | sh
#
# Or, pointing at a specific release or a local build:
#
#   … | EMBER_VERSION=v0.1.0 sh
#   EMBER_BINARY_URL=file://$PWD/target/release/ember EMBER_PANEL_SRC=$PWD/panel sh install.sh
#
# POSIX sh on purpose: a fresh server may not have bash.

set -eu

EMBER_REPO="${EMBER_REPO:-KumaVolt/ember}"
EMBER_BASE_URL="${EMBER_BASE_URL:-https://github.com/$EMBER_REPO}"
# A release tag such as v0.1.0, or "latest" to track the newest release.
EMBER_VERSION="${EMBER_VERSION:-latest}"
# Branch used for the panel when no release is pinned.
EMBER_BRANCH="${EMBER_BRANCH:-main}"
EMBER_BINARY_URL="${EMBER_BINARY_URL:-}"
EMBER_PORT="${EMBER_PORT:-7878}"
EMBER_PANEL_URL="${EMBER_PANEL_URL:-}"
EMBER_PANEL_SRC="${EMBER_PANEL_SRC:-}"
# Set when building an image: install everything, but do not start anything.
EMBER_SKIP_SERVICE="${EMBER_SKIP_SERVICE:-}"
EMBER_HOME="${EMBER_HOME:-/var/lib/ember}"
EMBER_ESW_DIR="${EMBER_ESW_DIR:-/opt/ember/esw}"
INSTALL_PATH="${INSTALL_PATH:-/usr/local/bin/ember}"
SERVICE_NAME=ember

# Exported, not merely set: every nested `ember` call below — esw install,
# esw php, status — resolves its own paths from the environment. Without this
# they fall back to root's ~/.ember and cannot find what we just installed.
export EMBER_HOME EMBER_ESW_DIR

say()  { printf '  %s\n' "$*"; }
step() { printf '\n\033[1m==>\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- preflight --------------------------------------------------------------

step "Checking this machine"

[ "$(id -u)" -eq 0 ] \
  || die "run as root (try: curl -fsSL https://raw.githubusercontent.com/$EMBER_REPO/main/install.sh | sudo sh)"

case "$(uname -s)" in
  Linux) ;;
  *) die "the installer supports Linux servers; for macOS run ember from source" ;;
esac

case "$(uname -m)" in
  x86_64|amd64)  ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
say "linux/$ARCH"

if command -v apt-get >/dev/null 2>&1;   then PKG=apt
elif command -v dnf   >/dev/null 2>&1;   then PKG=dnf
elif command -v yum   >/dev/null 2>&1;   then PKG=yum
else PKG=none
fi
say "package manager: $PKG"

fetch() {
  if   command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else die "need curl or wget to download"
  fi
}

# Port in use is worth catching now rather than after everything is installed.
# Skipped when building an image, where nothing is meant to be listening.
if [ -z "$EMBER_SKIP_SERVICE" ] &&
   command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ":$EMBER_PORT "; then
  die "port $EMBER_PORT is already in use — set EMBER_PORT to something else"
fi

# --- dependencies -----------------------------------------------------------

step "Installing dependencies"

# libpam is how Ember checks system passwords; ca-certificates is for the
# engine download. Both are usually present, so only install what is missing.
NEEDED=""
[ -f /etc/pam.d/other ] || NEEDED="$NEEDED libpam-runtime"
# certbot obtains and renews TLS certificates. Installing it here means its
# own renewal timer is in place from day one, rather than being something an
# operator has to remember before the first certificate expires.
case "$PKG" in
  apt)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # shellcheck disable=SC2086
    apt-get install -y -qq --no-install-recommends \
      ca-certificates libpam0g openssl certbot $NEEDED >/dev/null
    ;;
  dnf|yum)
    $PKG install -y -q ca-certificates pam openssl certbot >/dev/null
    ;;
  none)
    say "unknown package manager — assuming libpam and CA certificates are present"
    ;;
esac
say "ok"

# --- the binary -------------------------------------------------------------

step "Installing the ember binary"

if [ -n "$EMBER_BINARY_URL" ]; then
  URL="$EMBER_BINARY_URL"
elif [ "$EMBER_VERSION" = latest ]; then
  URL="$EMBER_BASE_URL/releases/latest/download/ember-linux-$ARCH"
else
  URL="$EMBER_BASE_URL/releases/download/$EMBER_VERSION/ember-linux-$ARCH"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "downloading $URL"
fetch "$URL" "$TMP/ember" || die "could not download the ember binary from $URL

  If no release has been published yet, build it and point the installer at it:

      cargo build --release
      sudo EMBER_BINARY_URL=file://\$PWD/target/release/ember \\
           EMBER_PANEL_SRC=\$PWD/panel sh install.sh"
[ -s "$TMP/ember" ] || die "downloaded binary is empty"

chmod 755 "$TMP/ember"
"$TMP/ember" --version >/dev/null 2>&1 || die "the downloaded binary does not run on this machine"

install -m 755 "$TMP/ember" "$INSTALL_PATH"
say "installed $INSTALL_PATH ($("$INSTALL_PATH" --version))"

# --- PAM --------------------------------------------------------------------

step "Configuring password authentication"

# Ember authenticates panel logins against real system accounts. Linux has no
# stack that is universally right to borrow, so Ember gets its own — delegating
# to the distribution's common stack where one exists.
if [ ! -f /etc/pam.d/ember ]; then
  if [ -f /etc/pam.d/common-auth ]; then
    cat > /etc/pam.d/ember <<'PAMEOF'
# Ember control panel — authenticates panel logins against system accounts.
@include common-auth
@include common-account
PAMEOF
  elif [ -f /etc/pam.d/system-auth ]; then
    cat > /etc/pam.d/ember <<'PAMEOF'
# Ember control panel — authenticates panel logins against system accounts.
auth     include  system-auth
account  include  system-auth
PAMEOF
  else
    cat > /etc/pam.d/ember <<'PAMEOF'
# Ember control panel — authenticates panel logins against system accounts.
auth     required  pam_unix.so
account  required  pam_unix.so
PAMEOF
  fi
  chmod 644 /etc/pam.d/ember
  say "wrote /etc/pam.d/ember"
else
  say "/etc/pam.d/ember already exists — left alone"
fi

# --- the engine -------------------------------------------------------------

step "Installing esw-engine"

mkdir -p "$EMBER_HOME" "$EMBER_ESW_DIR"
"$INSTALL_PATH" esw install || die "could not install esw-engine"

# An unprivileged account to execute panel code, so a panel bug is not root.
if ! id ember-esw >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin ember-esw 2>/dev/null \
    || useradd --system --no-create-home --shell /sbin/nologin ember-esw 2>/dev/null \
    || say "could not create ember-esw; the engine will run as nobody"
fi

# --- the panel --------------------------------------------------------------

step "Installing the panel"

PANEL_DIR="$EMBER_HOME/panel"
ESW_PHP="$INSTALL_PATH esw php --"

deploy_panel_from_dir() {
  # Build beside the live tree, then swap, so a failure never leaves a
  # half-written panel serving requests.
  rm -rf "$PANEL_DIR.new"
  mkdir -p "$PANEL_DIR.new"
  (cd "$1" && tar cf - .) | (cd "$PANEL_DIR.new" && tar xf -)
  [ -f "$PANEL_DIR.new/public/index.php" ] || { rm -rf "$PANEL_DIR.new"; return 1; }
  return 0
}

PANEL_STAGED=no

if [ -n "$EMBER_PANEL_SRC" ]; then
  say "using panel source from $EMBER_PANEL_SRC"
  if deploy_panel_from_dir "$EMBER_PANEL_SRC"; then
    PANEL_STAGED=yes
  else
    say "panel source looked wrong — skipped"
  fi
else
  if [ -n "$EMBER_PANEL_URL" ]; then
    PANEL_URL="$EMBER_PANEL_URL"
  elif [ "$EMBER_VERSION" = latest ]; then
    # The panel lives in the repository, so it can be fetched straight from the
    # branch archive — no release asset needed.
    PANEL_URL="$EMBER_BASE_URL/archive/refs/heads/$EMBER_BRANCH.tar.gz"
  else
    PANEL_URL="$EMBER_BASE_URL/archive/refs/tags/$EMBER_VERSION.tar.gz"
  fi
  say "downloading $PANEL_URL"
  if fetch "$PANEL_URL" "$TMP/panel.tar.gz" 2>/dev/null && [ -s "$TMP/panel.tar.gz" ]; then
    rm -rf "$TMP/panel" && mkdir -p "$TMP/panel"
    if tar xzf "$TMP/panel.tar.gz" -C "$TMP/panel" 2>/dev/null; then
      # Accept either a panel-only tarball or a full repository archive.
      SRC="$TMP/panel"
      if [ ! -f "$SRC/public/index.php" ]; then
        # -mindepth 1 matters: the extraction directory is itself called
        # "panel", so without it find matches the wrong thing first.
        SRC="$(find "$TMP/panel" -mindepth 1 -maxdepth 3 -type d -name panel 2>/dev/null | head -1)"
      fi
      if [ -n "$SRC" ] && [ -f "$SRC/public/index.php" ]; then
        deploy_panel_from_dir "$SRC" && PANEL_STAGED=yes
      fi
    fi
  fi
  [ "$PANEL_STAGED" = yes ] || say "no panel bundle available — keeping the built-in placeholder"
fi

if [ "$PANEL_STAGED" = yes ]; then
  # Dependencies are resolved here, on the server, using Ember's own PHP. The
  # machine needs no system PHP and no system Composer — the same pinned build
  # that will serve the panel is the one that compiles it.
  if [ -f "$PANEL_DIR.new/composer.json" ]; then
    step "Resolving panel dependencies"

    if [ ! -f "$EMBER_HOME/composer.phar" ]; then
      say "downloading composer"
      fetch "https://getcomposer.org/download/latest-stable/composer.phar" \
        "$EMBER_HOME/composer.phar" || die "could not download composer"
      chmod 644 "$EMBER_HOME/composer.phar"
    fi

    say "running composer install with ember's php $($ESW_PHP -r 'echo PHP_VERSION;')"
    ( cd "$PANEL_DIR.new" \
      && COMPOSER_HOME="$EMBER_HOME/.composer" \
         COMPOSER_ALLOW_SUPERUSER=1 \
         $ESW_PHP "$EMBER_HOME/composer.phar" install \
           --no-dev --no-interaction --no-progress \
           --prefer-dist --optimize-autoloader ) \
      || die "composer install failed for the panel"

    # Every install must get its own APP_SECRET. Shipping a shared or empty one
    # would make signed URIs and CSRF tokens forgeable across every deployment.
    if [ ! -f "$PANEL_DIR.new/.env.local" ]; then
      SECRET="$($ESW_PHP -r 'echo bin2hex(random_bytes(16));')"
      {
        echo "# Generated by install.sh — unique to this server."
        echo "APP_ENV=prod"
        echo "APP_DEBUG=0"
        echo "APP_SECRET=$SECRET"
      } > "$PANEL_DIR.new/.env.local"
      chmod 600 "$PANEL_DIR.new/.env.local"
      say "generated a unique APP_SECRET"
    fi

    say "warming the Symfony cache"
    ( cd "$PANEL_DIR.new" \
      && APP_ENV=prod APP_DEBUG=0 $ESW_PHP bin/console cache:warmup --no-interaction ) \
      >/dev/null 2>&1 || say "cache warmup skipped (it will build on first request)"
  fi

  # Swap the finished tree into place.
  rm -rf "$PANEL_DIR.old"
  [ -d "$PANEL_DIR" ] && mv "$PANEL_DIR" "$PANEL_DIR.old"
  mv "$PANEL_DIR.new" "$PANEL_DIR"
  rm -rf "$PANEL_DIR.old"
  say "panel installed at $PANEL_DIR"
fi

# Symfony writes its compiled container and logs at runtime, as the pool user.
mkdir -p "$PANEL_DIR/var"
if id ember-esw >/dev/null 2>&1; then
  chown -R ember-esw:ember-esw "$PANEL_DIR/var" 2>/dev/null || true
fi
chmod -R u+rwX,g+rwX "$PANEL_DIR/var" 2>/dev/null || true

# --- web server -------------------------------------------------------------

step "Setting up the web server"

# nginx serves customer domains. Ember serves the panel itself and does not use
# nginx for it, so installing this does not affect how you reach the panel.
if command -v nginx >/dev/null 2>&1; then
  say "nginx is already installed"
else
  case "$PKG" in
    apt)
      if apt-get install -y -qq --no-install-recommends nginx >/dev/null 2>&1; then
        say "installed nginx"
      else
        say "could not install nginx; customer sites will not be served"
      fi
      # Apache too, so a domain can be switched to it without installing
      # anything first. Only one of them listens on port 80 at a time.
      if apt-get install -y -qq --no-install-recommends apache2 >/dev/null 2>&1; then
        a2enmod proxy_fcgi rewrite >/dev/null 2>&1 || true
        say "installed apache (not started; nginx has port 80)"
      fi
      ;;
    dnf|yum)
      if $PKG install -y -q nginx >/dev/null 2>&1; then
        say "installed nginx"
      else
        say "could not install nginx; customer sites will not be served"
      fi
      if $PKG install -y -q httpd >/dev/null 2>&1; then
        say "installed apache (not started; nginx has port 80)"
      fi
      ;;
    *)
      say "unknown package manager; install nginx yourself to serve customer sites"
      ;;
  esac
fi

if command -v nginx >/dev/null 2>&1; then
  # Debian ships a default site on port 80 that would answer for every domain
  # that reaches this machine, including ones ember is configured to serve.
  # Both installed means both would want port 80. nginx is the default, so
  # apache stays stopped until a domain is switched to it.
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now apache2 >/dev/null 2>&1 || true
  fi

  if [ -e /etc/nginx/sites-enabled/default ]; then
    rm -f /etc/nginx/sites-enabled/default
    say "removed nginx's catch-all default site"
  fi

  # Generated vhosts are symlinked here, so it has to exist before the first
  # domain is created.
  mkdir -p /etc/nginx/sites-enabled

  if [ -z "$EMBER_SKIP_SERVICE" ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl enable --now nginx >/dev/null 2>&1; then
      say "nginx is running"
    else
      say "could not start nginx; check: systemctl status nginx"
    fi
  fi
fi

# --- database server --------------------------------------------------------

step "Setting up the database server"

# MariaDB hosts customer databases. Isolation is its own grant system: a user is
# granted rights on one database and cannot see any other, which holds even for
# a customer connecting directly with a MySQL client.
if command -v mariadb >/dev/null 2>&1 || command -v mysql >/dev/null 2>&1; then
  say "a mariadb client is already present"
else
  case "$PKG" in
    apt)
      if apt-get install -y -qq --no-install-recommends mariadb-server >/dev/null 2>&1; then
        say "installed mariadb-server"
      else
        say "could not install mariadb-server; databases will be unavailable"
      fi
      ;;
    dnf|yum)
      if $PKG install -y -q mariadb-server >/dev/null 2>&1; then
        say "installed mariadb-server"
      else
        say "could not install mariadb-server; databases will be unavailable"
      fi
      ;;
    *)
      say "unknown package manager; install mariadb-server yourself for databases"
      ;;
  esac
fi

if command -v mariadb >/dev/null 2>&1 || command -v mysql >/dev/null 2>&1; then
  MYSQL_BIN="$(command -v mariadb 2>/dev/null || command -v mysql)"

  # Customer databases must not be reachable from the internet. A fresh install
  # may listen on every interface depending on the distribution, so this is set
  # rather than assumed.
  for conf in /etc/mysql/mariadb.conf.d/99-ember.cnf /etc/my.cnf.d/99-ember.cnf; do
    conf_dir="$(dirname "$conf")"
    if [ -d "$conf_dir" ] && [ ! -f "$conf" ]; then
      cat > "$conf" <<'CNFEOF'
# Written by ember. Customer databases are reached over loopback only;
# exposing them to the network would undo the per-user isolation.
[mysqld]
bind-address = 127.0.0.1
skip-name-resolve
CNFEOF
      say "restricted mariadb to loopback ($conf)"
    fi
  done

  if [ -z "$EMBER_SKIP_SERVICE" ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl enable --now mariadb >/dev/null 2>&1 ||
       systemctl enable --now mysqld >/dev/null 2>&1; then
      say "mariadb is running"
    else
      say "could not start mariadb; check: systemctl status mariadb"
    fi

    # Wait for the socket before touching it: systemd returns as soon as the
    # unit is active, which is earlier than the server accepting connections.
    i=0
    while [ $i -lt 30 ]; do
      "$MYSQL_BIN" --protocol=socket -u root -e "SELECT 1;" >/dev/null 2>&1 && break
      i=$((i + 1))
      sleep 1
    done

    if "$MYSQL_BIN" --protocol=socket -u root -e "SELECT 1;" >/dev/null 2>&1; then
      # What mysql_secure_installation does, without the prompts. A default
      # install ships an anonymous account and a world-writable test database;
      # both would sit underneath the per-customer grants.
      "$MYSQL_BIN" --protocol=socket -u root <<'SQLEOF' >/dev/null 2>&1 || true
DELETE FROM mysql.global_priv WHERE User='';
DELETE FROM mysql.global_priv WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
SQLEOF
      say "removed anonymous accounts, the test database and remote root"
      say "server: $("$MYSQL_BIN" --protocol=socket -u root -N -B -e 'SELECT VERSION();' 2>/dev/null)"
    else
      say "mariadb did not accept connections in time; check systemctl status mariadb"
    fi
  else
    say "not started here; ember starts it on boot when it is installed"
  fi
fi

# --- certificate renewal ----------------------------------------------------

step "Setting up certificate renewal"

if command -v certbot >/dev/null 2>&1; then
  # Renewing rewrites the files, but a running web server keeps serving the old
  # certificate until told to reload. Without this hook, renewal succeeds and
  # visitors still see the expiring certificate.
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/ember-reload <<'HOOKEOF'
#!/bin/sh
# Installed by ember. Reloads the web servers so a renewed certificate is
# actually served; without this the old one stays live until a restart.
set -eu
for unit in nginx apache2 httpd; do
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$unit"; then
    systemctl reload "$unit" || true
  fi
done
HOOKEOF
  chmod 755 /etc/letsencrypt/renewal-hooks/deploy/ember-reload
  say "installed the renewal reload hook"

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl enable --now certbot.timer >/dev/null 2>&1; then
      say "certbot.timer enabled; renewal runs automatically"
    else
      say "could not enable certbot.timer; check renewal with: ember cert list"
    fi
  else
    say "no systemd — the certbot package's cron entry handles renewal"
  fi
else
  say "certbot not available; TLS can be added later with: ember cert issue <domain>"
fi

# --- service ----------------------------------------------------------------

step "Setting up the service"

if [ -n "$EMBER_SKIP_SERVICE" ]; then
  say "EMBER_SKIP_SERVICE set — installed but not started"
  printf '\n  Ember is installed. Start it with:\n\n      ember start --foreground\n\n'
  exit 0
fi

if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/$SERVICE_NAME.service <<EOF
[Unit]
Description=Ember control panel
Documentation=https://get.ember.sh
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
# Foreground: systemd supervises ember, ember supervises esw-engine.
ExecStart=$INSTALL_PATH start --foreground
Environment=EMBER_HOME=$EMBER_HOME
Environment=EMBER_ESW_DIR=$EMBER_ESW_DIR
Environment=EMBER_ESW_USER=ember-esw
Environment=EMBER_HOST=0.0.0.0
Environment=EMBER_PORT=$EMBER_PORT
# This machine is the one being managed, so account management is expected.
Environment=EMBER_MODE=host
Restart=on-failure
RestartSec=5s
KillSignal=SIGTERM
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now $SERVICE_NAME >/dev/null 2>&1 || die "could not start the ember service"

  # Give it a moment, then confirm it is actually serving rather than crash-looping.
  i=0
  while [ $i -lt 30 ]; do
    if "$INSTALL_PATH" --version >/dev/null 2>&1 &&
       EMBER_HOME="$EMBER_HOME" "$INSTALL_PATH" status 2>/dev/null | grep -q running; then
      break
    fi
    i=$((i + 1))
    sleep 1
  done

  if ! "$INSTALL_PATH" status 2>/dev/null | grep -q running; then
    printf '\n'
    say "the service did not come up. Recent log:"
    journalctl -u $SERVICE_NAME -n 20 --no-pager 2>/dev/null || true
    die "ember failed to start"
  fi
  say "systemd unit $SERVICE_NAME is enabled and running"
else
  say "no systemd here — starting ember directly"
  # Same environment the unit would provide. EMBER_HOST especially: without it
  # ember binds loopback and nothing outside this machine can reach the panel.
  EMBER_MODE=host \
  EMBER_HOME="$EMBER_HOME" \
  EMBER_ESW_DIR="$EMBER_ESW_DIR" \
  EMBER_ESW_USER=ember-esw \
  EMBER_HOST=0.0.0.0 \
  EMBER_PORT="$EMBER_PORT" \
    "$INSTALL_PATH" start >/dev/null 2>&1 || die "could not start ember"
  say "started on 0.0.0.0:$EMBER_PORT"
  say "to run it again after a reboot:"
  say "  EMBER_MODE=host EMBER_HOME=$EMBER_HOME EMBER_HOST=0.0.0.0 $INSTALL_PATH start"
fi

# --- done -------------------------------------------------------------------

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "${IP:-}" ] || IP="your-server-ip"

cat <<EOF

  Ember is installed and running.

  Open this to create your administrator:

      http://$IP:$EMBER_PORT/

  The first visit walks you through setup. Nothing else can sign in until
  you have done that.

  Useful commands:
      ember status
      ember logs
      ember recover        restore access if you are locked out
      systemctl restart $SERVICE_NAME

EOF

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "^Status: active"; then
  say "ufw is active — allow the panel with: ufw allow $EMBER_PORT/tcp"
  printf '\n'
fi
