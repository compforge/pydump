# Python Analyzer

This directory contains the Python reference implementation of Pydump Analyzer. It has no runtime
dependencies, uses mmap for the input artifact, and exposes the `pydump_analyzer` command through
the repository's root Python package.

Run formatting, static checks, and tests from the repository root:

```bash
make fix
make lint
make test
```
