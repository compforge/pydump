# Backlog

## Native ptrace Loader hardening

The existing `pydump-loader` implementation remains available, but further architecture work is
deferred while GDB is the primary Loader path. Before ptrace becomes a release-grade fallback, it
must preserve every target thread state that its bootstrap can modify, including optional AArch64
FPSIMD, SVE/SME, TLS, and GCS regsets; use the target page size; and replace timing-based clone
completion with an explicit lifecycle protocol.

[CRIU/libcompel](https://github.com/checkpoint-restore/criu/tree/criu-dev/compel) is the reference
for ptrace state handling. [Frida Core](https://github.com/frida/frida-core/tree/main/src/linux) is
the reference for staged bootstrap, Agent transport, diagnostics, and cleanup. These projects are
design references only; Pydump does not vendor or link them.
