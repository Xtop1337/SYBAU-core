# Interoperability tests against the official Xray and sing-box images.
#
#   docker build -f tests/interop/Dockerfile -t sybau-interop .
#   docker run --rm sybau-interop
FROM ghcr.io/xtls/xray-core:26.3.27 AS xray
FROM ghcr.io/sagernet/sing-box:v1.14.4 AS singbox

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p sybau

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 curl openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=build /src/target/release/sybau /usr/local/bin/sybau
COPY tests/interop/run.py /interop/run.py
ENV XRAY_BIN=/usr/local/bin/xray SINGBOX_BIN=/usr/local/bin/sing-box SYBAU_BIN=/usr/local/bin/sybau
RUN xray version && sing-box version && sybau --version
COPY tests/interop/client_formats.py /interop/client_formats.py
# The client config is written natively, then as Xray config, sing-box
# config and share link (each checked by the real program, converted by sybau).
CMD ["sh", "-c", "set -e; for f in native xray sing-box link; do echo \"== client format: $f\"; python3 /interop/run.py --client-format $f; done"]
