# Pydump

Pydump captures the live object graph of a CPython process while keeping heap-sized state out of
the target process. A small C agent streams object facts; the Python Collector owns the work queue,
visited-address set, and output file.

The generated artifact uses PyHeap's `.pyheap` v1 format, so existing PyHeap UI and Doctor analysis
can read it.

Pydump is inspired by [PyHeap](https://github.com/ivanyu/pyheap), whose GDB-based heap dumper,
artifact format, and analysis workflow established the foundation for this project.

## Status

Pydump is alpha software. The protocol, Collector, artifact writer, and CPython 3.10+ native agent
are implemented. Native attach requires Linux glibc, GDB, and an agent built for the target CPython
minor version. CPython 3.10 and 3.11 use minor-specific internal GC layouts and therefore require
their real attach matrix before a build is released.

Live capture pauses Python execution while the Agent holds the GIL. This prototype is not ready for
production use until Linux GDB attach, timeout recovery, target-memory budgets, and the full
3.10–3.14 x86_64/AArch64 matrix have passed.

## Build

```bash
uv sync --extra dev
make build-agent
```

The agent is written to `native/build/pydump-agent-<python-minor>-<arch>.so`. Build it with the same
CPython minor used by the target process.

## Capture

```bash
uv run pyheap_dump --pid 1234 --file process.pyheap \
  --agent native/build/pydump-agent-3.12-x86_64.so
```

The familiar PyHeap flags remain available: `--str-repr-len`, `--no-attribute`,
`--ignore-compatibility-checks`, and `--force-shadow`. Pydump never calls application-defined
`__str__`, `__repr__`, `__sizeof__`, descriptors, or attribute hooks. The current release emits a
safe type/address preview and leaves attributes and thread frames empty; explanatory metadata is
therefore less detailed than PyHeap while the object graph remains the primary compatibility
contract.

See [the design](docs/design.md) for the memory ownership and safety model.

## Verify

```bash
make fix
make lint
make test
make test-native
make test-compat  # when fork-pyheap is available beside this checkout
```
