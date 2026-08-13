# Contracts

This directory is the language-neutral boundary shared by Capture, Analyzer implementations, and
consumers. `heap-v1.md` pins the accepted artifact semantics; `analysis-v1.md` owns the Pydump
analysis JSON. Files under `testdata` are executable contract fixtures, not examples owned by one
implementation.

`testdata/generate.py` makes the binary fixture reproducible and seeds the expected JSON with the
Python reference implementation. Regenerating that JSON is still a contract change: review the
diff against `analysis-v1.md`, then require both Python and Go tests to accept it. The generator
does not make Python the protocol owner.
