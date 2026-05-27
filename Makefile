IMAGE         ?= field-cage:dev
DEV_IMAGE     ?= field-cage:dev-ubuntu
BUILDER_IMAGE ?= field-cage:builder
GOPATH_VOL    ?= field-cage-gopath

.PHONY: tidy build run run-dev test setup-hooks clean

# Run go mod tidy inside a Go container to generate go.sum (run once before build)
tidy:
	docker run --rm \
		-v $(CURDIR):/src \
		-w /src \
		golang:1.22-bullseye \
		go mod tidy

# Build the release Docker image (distroless runtime, matches distributed artifact)
build:
	docker build --target runtime -t $(IMAGE) .

# Run with the privileges required for eBPF
run:
	docker run --rm \
		--privileged \
		-v /sys/kernel/debug:/sys/kernel/debug:ro \
		-v /sys/fs/bpf:/sys/fs/bpf \
		$(IMAGE)

# Local verification: Ubuntu-based image with curl/wget so traffic can be
# generated inside the same container as the agent. Runs detached; generate
# traffic and watch logs as printed below.
run-dev:
	docker build --target runtime-dev -t $(DEV_IMAGE) .
	-docker rm -f fc-dev 2>/dev/null
	docker run --rm -d --privileged --name fc-dev \
		-v /sys/kernel/debug:/sys/kernel/debug:ro \
		-v /sys/fs/bpf:/sys/fs/bpf \
		$(DEV_IMAGE)
	@echo ""
	@echo "agent started (container: fc-dev). Verify with:"
	@echo "  docker exec fc-dev curl -s http://example.com -o /dev/null"
	@echo "  docker logs -f fc-dev"
	@echo "Stop with: docker stop fc-dev"

# Run unit tests inside the builder container.
# Host source is mounted so the current working tree is tested.
# A named volume caches the Go module download between runs.
test:
	docker build --target builder -t $(BUILDER_IMAGE) -q .
	docker run --rm \
		-v "$(CURDIR):/src" \
		-v "$(GOPATH_VOL):/go" \
		-w /src \
		$(BUILDER_IMAGE) \
		sh -c "go generate ./internal/ebpf/... && go test -count=1 ./..."

# Remove bpf2go-generated files and cached Docker volumes
clean:
	rm -f internal/ebpf/connect_bpf*.go internal/ebpf/connect_bpf*.o
	rm -f internal/ebpf/dns_bpf*.go internal/ebpf/dns_bpf*.o
	-docker volume rm $(GOPATH_VOL) 2>/dev/null

# Configure git to use the committed .githooks/ directory.
# Run once after cloning: make setup-hooks
setup-hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-push
	@echo "pre-push hook enabled: 'make test' will run before each push."
