# Ember — single-service container.
#
# One process tree: the `ember` binary is PID 1 and supervises esw-engine as its
# child. No nginx, no supervisord, no separate PHP container.
#
# This file deliberately does NOT reimplement setup. It compiles the binary and
# then runs `install.sh` — the same script a server gets from `curl | sh`. The
# panel's dependencies are resolved by that script using Ember's own PHP, so
# there is no Composer stage here and no second dialect of the setup steps.

# --- build the binary -------------------------------------------------------
FROM rust:1.96-slim-bookworm AS builder

WORKDIR /src

# libpam0g-dev: Ember links against libpam to check system passwords.
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libpam0g-dev \
 && rm -rf /var/lib/apt/lists/*

# Warm the dependency layer first so source edits do not refetch the world.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release \
 && rm -rf src

COPY src ./src
# Cargo skips rebuilding when only mtime changed, so force the real main.rs.
RUN touch src/main.rs && cargo build --release


# --- fetch the engine -------------------------------------------------------
# Its own stage so the ~30 MB download caches independently of any code change.
FROM builder AS engine

ENV EMBER_ESW_DIR=/opt/ember/esw
RUN /src/target/release/ember esw install


# --- runtime ----------------------------------------------------------------
FROM debian:bookworm-slim

# curl: needed by install.sh and by the healthcheck below. Everything else the
# installer pulls in itself.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

# The artefacts install.sh will consume, staged where it can find them.
COPY --from=builder /src/target/release/ember /tmp/dist/ember
COPY --from=engine  /opt/ember/esw            /opt/ember/esw
COPY panel      /tmp/dist/panel
COPY install.sh /tmp/dist/install.sh

# The same script a server runs, in build mode: install everything, start
# nothing. It writes /etc/pam.d/ember, creates ember-esw, deploys the panel and
# resolves its dependencies with Ember's own PHP — none of it duplicated here.
RUN EMBER_SKIP_SERVICE=1 \
    EMBER_BINARY_URL=file:///tmp/dist/ember \
    EMBER_PANEL_SRC=/tmp/dist/panel \
    EMBER_HOME=/var/lib/ember \
    EMBER_ESW_DIR=/opt/ember/esw \
    sh /tmp/dist/install.sh \
 && rm -rf /tmp/dist

# EMBER_MODE=host: inside the container, the container *is* the machine Ember
# manages, so account management is expected. On a developer's laptop the
# default stays `isolated` and the same binary refuses to touch real accounts.
#
# Panel users are system users, so they live in this container's /etc/passwd and
# /etc/shadow — part of the writable layer. Persist those too if accounts must
# survive an image update.
ENV EMBER_HOME=/var/lib/ember \
    EMBER_ESW_DIR=/opt/ember/esw \
    EMBER_ESW_USER=ember-esw \
    EMBER_MODE=host \
    EMBER_HOST=0.0.0.0 \
    EMBER_PORT=7878

EXPOSE 7878

# Unauthenticated liveness probe; every other route requires a session.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${EMBER_PORT}/healthz" || exit 1

# Foreground on purpose: ember is PID 1 and handles SIGTERM itself, so
# `docker stop` drains in-flight requests instead of killing the engine.
ENTRYPOINT ["ember"]
CMD ["start", "--foreground"]
