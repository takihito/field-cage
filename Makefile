IMAGE         ?= field-cage:dev
BUILDER_IMAGE ?= field-cage:builder
GOPATH_VOL    ?= field-cage-gopath

.PHONY: tidy build run test setup-hooks

# Run go mod tidy inside a Go container to generate go.sum (run once before build)
tidy:
	docker run --rm \
		-v $(CURDIR):/src \
		-w /src \
		golang:1.22-bullseye \
		go mod tidy

# Build the Docker image (compiles eBPF + Go binary)
build:
	docker build -t $(IMAGE) .

# Run with the privileges required for eBPF
run:
	docker run --rm \
		--privileged \
		-v /sys/kernel/debug:/sys/kernel/debug:ro \
		-v /sys/fs/bpf:/sys/fs/bpf \
		$(IMAGE)

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

# Configure git to use the committed .githooks/ directory.
# Run once after cloning: make setup-hooks
setup-hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-push
	@echo "pre-push hook enabled: 'make test' will run before each push."
