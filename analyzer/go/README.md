# Go Analyzer

The Go implementation builds a standalone `pydump_analyzer` binary. It streams the input artifact,
interns 64-bit addresses into `uint32` indexes, and stores referent and inbound-reference graphs in
compact CSR arrays.

```bash
go build -o pydump_analyzer ./cmd/pydump-analyzer
go test ./...
```

Its normalized JSON output must match the Python reference implementation on every shared fixture
under `contracts/testdata`.
