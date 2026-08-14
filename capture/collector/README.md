# Pydump Collector

The Python Collector selects an Agent Loader, owns heap-sized traversal state, and writes the
completed heap artifact. GDB and ptrace are parallel Loader strategies; the native ptrace helper
and injected C Agent are built separately under `capture/loader/injector` and `capture/agent`.

The repository root README contains the supported capture command and development workflow.
