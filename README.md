# Pydump

Pydump captures the live object graph of a CPython process while keeping heap-sized state out of
the target process. A small C agent streams object facts; the Python Collector owns the work queue,
visited-address set, and output file.

The generated artifact uses PyHeap's `.pyheap` v1 format. Independent Python and Go analyzers read
that artifact and emit the language-neutral `pydump.analysis/v1` JSON protocol.

Pydump is inspired by [PyHeap](https://github.com/ivanyu/pyheap), whose heap artifact format and
analysis workflow established the foundation for this project.
The remote loading design was also informed by
[kubo/injector](https://github.com/kubo/injector); Pydump does not link or vendor that project.

## Status

Pydump is alpha software. The protocol, Collector, artifact writer, CPython 3.10+ native Agent,
GDB Loader, and static Linux ptrace Loader for x86_64/AArch64 are implemented. Native capture
requires `SYS_PTRACE` and an Agent built for the target CPython minor version.
CPython 3.10 and 3.11 use minor-specific internal GC layouts and therefore require their real attach
matrix before a build is released.

Live capture pauses Python execution while the Agent holds the GIL. This prototype is not ready for
production use until Linux ptrace attach, timeout recovery, target-memory budgets, and the full
3.10–3.14 x86_64/AArch64 matrix have passed.

## Build

```bash
uv sync --all-packages
make build-agent
make build-ptrace-loader
make build-go
```

The Agent is written to `capture/agent/build/pydump-agent-<python-minor>-<arch>.so`. Build it with
the same CPython minor used by the target process. `make build-ptrace-loader` produces static
x86_64 and AArch64 helpers under the Collector package; release wheels include the matching helper.

## Capture

```bash
uv run --package pydump pyheap_dump --pid 1234 --file process.pyheap \
  --agent capture/agent/build/pydump-agent-3.12-x86_64.so
```

The Collector probes the target architecture and libc, then selects an Agent Loader. `auto`
prefers GDB when it is available and falls back to the bundled ptrace Loader. Use
`--loader gdb|ptrace` to require a strategy; `--gdb` and `--ptrace-loader` select an explicit
executable.

The familiar PyHeap flags remain available: `--str-repr-len`, `--no-attribute`,
`--ignore-compatibility-checks`, and `--force-shadow`. Pydump never calls application-defined
`__str__`, `__repr__`, `__sizeof__`, descriptors, or attribute hooks. The current release emits a
safe type/address preview and leaves attributes and thread frames empty; explanatory metadata is
therefore less detailed than PyHeap while the object graph remains the primary compatibility
contract.

See [the kernel](docs/kernel.md) for the memory ownership and safety model.

## Analyze

```bash
uv run --package pydump-analyzer pydump_analyzer summary --file process.pyheap
uv run --package pydump-analyzer pydump_analyzer retained-heap \
  --file process.pyheap --format json --top-n 100
```

`summary` reads the artifact and emits `pydump.analysis/v1` JSON without calculating retained
sizes. `retained-heap` additionally builds the inbound-reference index and retained-size data; this
is an O(N) offline workload and can use substantial memory on a large heap. Both commands run in
the analyzer process after capture and do not allocate analysis state in the target process or its
container.

Analyzer implementations live under [`analyzer/<language>`](analyzer/). Python ships as the
independent `pydump-analyzer` package; Go builds a standalone `pydump_analyzer` binary. Both use
[`contracts`](contracts/) and the same golden corpus rather than depending on each other. Neither
includes or depends on PyHeap's Flask UI.

## Verify

```bash
make fix
make lint
make test
make test-native
make test-ptrace-loader  # Linux only
make test-compat  # when fork-pyheap is available beside this checkout
```

Performance investigations use isolated transport and artifact-sink benchmarks so measurement does
not change live-capture behavior:

```bash
make benchmark-transport
make benchmark-writer
make benchmark-native  # Linux only; streams a synthetic target through the native Agent
```
