# bw2fabroker image: the broker plus the Bitwarden CLI. Runs as a non-root user.
FROM golang:1.24.7-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ ./cmd/broker ./cmd/broker-get

FROM node:22.20.0-bookworm-slim
ARG BW_VERSION=2026.10.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g --no-fund --no-audit @bitwarden/cli@${BW_VERSION} \
 && npm cache clean --force \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin broker \
 && mkdir -p /data /agent \
 && chown broker:broker /data /agent
COPY --from=build /out/broker /out/broker-get /usr/local/bin/
ENV BROKER_CONFIG=/data/config/config.toml \
    BROKER_ADMIN_SOCKET=/data/run/admin.sock \
    BITWARDENCLI_APPDATA_DIR=/data/bw \
    TS_SOCKET=/var/run/tailscale/tailscaled.sock \
    HOME=/data \
    NODE_NO_WARNINGS=1
USER broker
VOLUME ["/data"]
ENTRYPOINT ["broker"]
CMD ["start"]
