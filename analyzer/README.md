# Pydump Analyzer

Pydump Analyzer is a family of headless, offline heap analyzers. Each implementation reads the
same completed heap artifact and emits the language-neutral `pydump.analysis/v1` JSON protocol.
Capture, UI, Kubernetes orchestration, and Doctor-specific reporting stay outside this directory.

## Layout

```text
analyzer/
├── python/     # Python reference implementation and tests
└── go/         # Standalone Go implementation and tests
```

Each language owns its build files, source, and local tests under `analyzer/<language>`. New
implementations must use the repository-level [`contracts`](../contracts/) and golden corpus rather
than importing another language implementation or defining a parallel schema.

The Python implementation is distributed with the root `pydump` package:

```bash
uv run --package pydump-analyzer pydump_analyzer summary --file process.pyheap
uv run --package pydump-analyzer pydump_analyzer retained-heap \
  --file process.pyheap --format json
```

Analyzer processes may use O(N) memory. Callers should run them outside the target process and
apply their own timeout and memory policy.
