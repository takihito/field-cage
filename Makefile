IMAGE ?= field-cage:dev

.PHONY: tidy build run

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
