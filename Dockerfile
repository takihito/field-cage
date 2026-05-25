# Stage 1: compile eBPF C → Go bindings → static binary
FROM golang:1.22-bullseye AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-amd64 \
    && rm -rf /var/lib/apt/lists/*

# Install bpf2go at the version pinned in go.mod
RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.14.0

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Generate Go bindings from the eBPF C program
RUN go generate ./internal/ebpf/...

# Build fully-static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -o /out/field-cage ./cmd/agent

# Stage 2: minimal runtime image
FROM gcr.io/distroless/static
COPY --from=builder /out/field-cage /field-cage
ENTRYPOINT ["/field-cage"]
