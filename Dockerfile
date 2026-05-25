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

# Stage 2: minimal runtime image
FROM gcr.io/distroless/static
COPY --from=builder /out/field-cage /field-cage
ENTRYPOINT ["/field-cage"]
