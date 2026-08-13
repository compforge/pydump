# Pydump Collector

The Python Collector coordinates the architecture-specific ptrace injector, owns heap-sized
traversal state, and writes the completed heap artifact. The static injector and injected C Agent
are built separately from `capture/injector` and `capture/agent`.

The repository root README contains the supported capture command and development workflow.
