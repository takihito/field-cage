# Stage 1: compile eBPF C → Go bindings → static binary
FROM golang:1.22-bullseye AS builder

RUN set -e; \
    apt-get update; \
    apt-get install -y --no-install-recommends clang llvm libbpf-dev; \
    apt-get install -y --no-install-recommends "linux-headers-$(dpkg --print-architecture)"; \
    rm -rf /var/lib/apt/lists/*

# Create /usr/include/asm symlink required when compiling for -target bpf.
# linux-headers installs asm/ under the arch triplet path; clang's BPF target
# needs it at a plain /usr/include/asm location.
RUN case $(uname -m) in \
      x86_64)  TRIPLET=x86_64-linux-gnu ;; \
      aarch64) TRIPLET=aarch64-linux-gnu ;; \
      *) echo "Unsupported arch: $(uname -m)" && exit 1 ;; \
    esac && \
    ln -sf /usr/include/${TRIPLET}/asm /usr/include/asm

# Install bpf2go at the version pinned in go.mod
RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.14.0

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Generate Go bindings from the eBPF C program
RUN go generate ./internal/ebpf/...

# Build fully-static binary
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -o /out/field-cage ./cmd/agent

# Stage 2 (release): minimal runtime image — matches the distributed artifact.
# eBPF requires CAP_BPF / CAP_SYS_ADMIN on the running process. The :nonroot
# variant runs as UID 65532, which cannot hold capabilities even under
# --privileged, so BPF_PROG_LOAD returns EPERM. Use the root variant.
FROM gcr.io/distroless/static-debian12 AS runtime
COPY --from=builder /out/field-cage /field-cage
ENTRYPOINT ["/field-cage"]

# Stage 3 (dev): Ubuntu-based image for local verification. Ships curl/wget so
# outbound traffic can be generated inside the same container (and same network
# namespace) as the agent, avoiding the --network container: dance that the
# shell-less distroless image requires. Ubuntu also matches the ubuntu-latest
# CI runner. NOT a distribution artifact.
FROM ubuntu:24.04 AS runtime-dev
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl wget iproute2 dnsutils \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/field-cage /field-cage
ENTRYPOINT ["/field-cage"]
