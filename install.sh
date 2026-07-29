#!/bin/sh
# Ember installer — set up the control panel on a fresh server.
#
#   curl -fsSL https://get.ember.sh | sh
#
# Or, pointing at a specific build:
#
#   curl -fsSL https://get.ember.sh | EMBER_VERSION=0.1.0 sh
#   EMBER_BINARY_URL=http://…/ember-linux-x86_64 sh install.sh
#
# POSIX sh on purpose: a fresh server may not have bash.

set -eu

EMBER_BASE_URL="${EMBER_BASE_URL:-https://get.ember.sh}"
EMBER_VERSION="${EMBER_VERSION:-latest}"
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

say()  { printf '  %s\n' "$*"; }
step() { printf '\n\033[1m==>\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- preflight --------------------------------------------------------------

step "Checking this machine"

[ "$(id -u)" -eq 0 ] || die "run as root (try: curl -fsSL $EMBER_BASE_URL | sudo sh)"

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
case "$PKG" in
  apt)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # shellcheck disable=SC2086
    apt-get install -y -qq --no-install-recommends ca-certificates libpam0g $NEEDED >/dev/null
    ;;
  dnf|yum)
    $PKG install -y -q ca-certificates pam >/dev/null
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
else
  URL="$EMBER_BASE_URL/releases/$EMBER_VERSION/ember-linux-$ARCH"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "downloading $URL"
fetch "$URL" "$TMP/ember" || die "could not download the ember binary from $URL"
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
EMBER_HOME="$EMBER_HOME" EMBER_ESW_DIR="$EMBER_ESW_DIR" "$INSTALL_PATH" esw install \
  || die "could not install esw-engine"

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
  deploy_panel_from_dir "$EMBER_PANEL_SRC" && PANEL_STAGED=yes \
    || say "panel source looked wrong — skipped"
else
  PANEL_URL="${EMBER_PANEL_URL:-$EMBER_BASE_URL/releases/$EMBER_VERSION/ember-panel.tar.gz}"
  say "downloading $PANEL_URL"
  if fetch "$PANEL_URL" "$TMP/panel.tar.gz" 2>/dev/null && [ -s "$TMP/panel.tar.gz" ]; then
    rm -rf "$TMP/panel" && mkdir -p "$TMP/panel"
    if tar xzf "$TMP/panel.tar.gz" -C "$TMP/panel" 2>/dev/null; then
      SRC="$TMP/panel"
      [ -f "$SRC/public/index.php" ] || SRC="$TMP/panel/$(ls "$TMP/panel" | head -1)"
      deploy_panel_from_dir "$SRC" && PANEL_STAGED=yes
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

  if ! EMBER_HOME="$EMBER_HOME" "$INSTALL_PATH" status 2>/dev/null | grep -q running; then
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
