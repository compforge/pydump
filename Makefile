.PHONY: benchmark-native benchmark-transport benchmark-writer build-agent build-go build-ptrace-loader build-python fix lint test test-compat test-native test-ptrace-loader

PYTHON ?= python3
PYHEAP_UI_SRC ?= ../fork-pyheap/pyheap-ui/src

fix:
	uv run --all-packages ruff format .
	uv run --all-packages ruff check --fix .
	cd analyzer/go && gofmt -w .
	cd capture/loader/injector && gofmt -w .

lint:
	uv run --all-packages ruff format --check .
	uv run --all-packages ruff check .
	uv run --all-packages mypy capture/collector/src analyzer/python/src
	test -z "$$(gofmt -l analyzer/go)"
	cd analyzer/go && go vet ./...
	test -z "$$(gofmt -l capture/loader/injector)"
	cd capture/loader/injector && GOOS=linux GOARCH=amd64 go vet ./...
	cd capture/loader/injector && GOOS=linux GOARCH=arm64 go vet ./...

test:
	uv run --all-packages pytest
	cd analyzer/go && go test ./...

test-compat:
	PYTHONPATH=capture/collector/src:$(PYHEAP_UI_SRC) uv run --all-packages pytest \
		capture/collector/tests/test_heap_writer.py::test_upstream_pyheap_reader_accepts_artifact

test-native: build-agent
	PYDUMP_NATIVE_AGENT=$$(find capture/agent/build -name 'pydump-agent-*.so' -print -quit) \
		PYTHONPATH=capture/collector/src uv run --all-packages pytest capture/collector/tests/test_native_agent.py

test-ptrace-loader:
	cd capture/loader/injector && go test ./...

benchmark-transport:
	uv run --all-packages python capture/collector/benchmarks/benchmark_transport.py

benchmark-writer:
	uv run --all-packages python capture/collector/benchmarks/benchmark_writer.py

benchmark-native: build-agent
	PYTHONPATH=capture/collector/src $(PYTHON) capture/collector/benchmarks/benchmark_native_capture.py \
		--agent $$(find capture/agent/build -name 'pydump-agent-*.so' -print -quit)

build-agent:
	$(MAKE) -C capture/agent PYTHON=$(PYTHON)

build-python: build-ptrace-loader
	uv build --package pydump --out-dir dist/capture
	uv build --package pydump-analyzer --out-dir dist/analyzer-python

build-go:
	mkdir -p dist/analyzer-go
	cd analyzer/go && go build -o ../../dist/analyzer-go/pydump_analyzer ./cmd/pydump-analyzer
	cp LICENSE NOTICE dist/analyzer-go/

build-ptrace-loader:
	mkdir -p capture/collector/src/pydump/loader/bin
	cd capture/loader/injector && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
		-ldflags='-s -w' \
		-o ../../collector/src/pydump/loader/bin/pydump-injector-linux-x86_64 \
		./cmd/pydump-injector
	cd capture/loader/injector && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
		-ldflags='-s -w' \
		-o ../../collector/src/pydump/loader/bin/pydump-injector-linux-aarch64 \
		./cmd/pydump-injector
