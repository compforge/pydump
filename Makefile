.PHONY: build-agent fix lint test test-compat test-native

PYTHON ?= python3

fix:
	uv run --extra dev ruff format .
	uv run --extra dev ruff check --fix .

lint:
	uv run --extra dev ruff format --check .
	uv run --extra dev ruff check .
	uv run --extra dev mypy src

test:
	uv run --extra dev pytest

test-compat:
	PYTHONPATH=src:../fork-pyheap/pyheap-ui/src uv run --extra dev pytest \
		tests/test_heap_writer.py::test_upstream_pyheap_reader_accepts_artifact

test-native: build-agent
	PYDUMP_NATIVE_AGENT=$$(find native/build -name 'pydump-agent-*.so' -print -quit) \
		PYTHONPATH=src $(PYTHON) -m pytest tests/test_native_agent.py

build-agent:
	$(MAKE) -C native PYTHON=$(PYTHON)
