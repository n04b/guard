# syntax=docker/dockerfile:1.7
#
# Guard: Rauthy + Caddy + guard-sync under s6-overlay in one image.
#
#   docker build -t guard:latest .
#   docker buildx build --platform linux/amd64,linux/arm64 -t guard:latest .

ARG RAUTHY_VERSION=0.37.2
ARG CADDY_VERSION=2.11.9
ARG S6_OVERLAY_VERSION=3.2.3.2
ARG GO_VERSION=1.24

# ---------- upstream binaries ----------
FROM ghcr.io/sebadob/rauthy:${RAUTHY_VERSION} AS rauthy
FROM caddy:${CADDY_VERSION} AS caddy

# ---------- guard-sync ----------
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/guard-sync ./cmd/guard-sync

# ---------- runtime ----------
# Debian (glibc) because the Rauthy binary is built for glibc.
FROM debian:bookworm-slim
ARG S6_OVERLAY_VERSION
ARG TARGETARCH
ARG VERSION=dev

LABEL org.opencontainers.image.title="Guard" \
      org.opencontainers.image.description="Single-container auth server: Rauthy (OIDC, passkeys) + Caddy (TLS, reverse proxy)" \
      org.opencontainers.image.version="${VERSION}"

ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz \
    https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz.sha256 \
    https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz \
    https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz.sha256 \
    https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-aarch64.tar.xz \
    https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-aarch64.tar.xz.sha256 \
    /tmp/s6/

COPY --from=rauthy /app/rauthy /usr/local/bin/rauthy
COPY --from=caddy /usr/bin/caddy /usr/local/bin/caddy
COPY --from=build /out/guard-sync /usr/local/bin/guard-sync

# s6-overlay (checksums verified), file capability so Caddy can bind 80/443
# as the unprivileged user, and the "guard" user (uid 10001).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates tzdata xz-utils libcap2-bin; \
    case "$TARGETARCH" in \
      amd64) S6_ARCH=x86_64 ;; \
      arm64) S6_ARCH=aarch64 ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    cd /tmp/s6; \
    sha256sum -c s6-overlay-noarch.tar.xz.sha256; \
    sha256sum -c "s6-overlay-${S6_ARCH}.tar.xz.sha256"; \
    tar -C / -Jxpf s6-overlay-noarch.tar.xz; \
    tar -C / -Jxpf "s6-overlay-${S6_ARCH}.tar.xz"; \
    rm -rf /tmp/s6; \
    setcap cap_net_bind_service=+ep /usr/local/bin/caddy; \
    apt-get purge -y --auto-remove xz-utils libcap2-bin; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 10001 guard; \
    useradd --system --uid 10001 --gid guard --home-dir /data --shell /usr/sbin/nologin guard; \
    mkdir -p /data /config /certs; \
    chown guard:guard /data; \
    chmod 0700 /data

COPY docker/rootfs/etc/s6-overlay/ /etc/s6-overlay/
COPY config.example/ /usr/share/guard/config.example/
# Do not depend on the file modes of the working copy.
RUN chmod -R u=rwX,go=rX /etc/s6-overlay /usr/share/guard \
 && chmod 0755 /etc/s6-overlay/scripts/* /etc/s6-overlay/s6-rc.d/*/run /etc/s6-overlay/s6-rc.d/*/finish

ENV S6_BEHAVIOUR_IF_STAGE2_FAILS=2 \
    S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0 \
    S6_KILL_GRACETIME=5000 \
    S6_SERVICES_GRACETIME=10000 \
    S6_VERBOSITY=1 \
    GUARD_CONFIG_DIR=/config \
    GUARD_DATA_DIR=/data \
    XDG_DATA_HOME=/data

EXPOSE 80 443
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD ["/usr/local/bin/guard-sync", "healthcheck"]

ENTRYPOINT ["/init"]
