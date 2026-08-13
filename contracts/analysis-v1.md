# `pydump.analysis/v1`

## Purpose

`pydump.analysis/v1` is the language-neutral result of analyzing one completed heap artifact. It
separates artifact parsing and retained-heap calculation from Doctor, UI, and other consumers.
Implementations may differ internally, but the same artifact and command options must produce the
same JSON value.

The current input is the PyHeap v1 artifact format. Input compatibility does not transfer ownership
of the analysis protocol: Pydump owns this schema and evolves it independently.

## Document

The top-level object contains:

- `schema`: exactly `pydump.analysis/v1`;
- `source`: artifact SHA-256, byte size, heap format version, creation time, and whether string
  representations are present;
- `heap`: object, type, thread and referent counts plus total shallow bytes;
- `types`: object count and shallow bytes grouped by type;
- `threads`: thread metadata, frames, locals and optional retained bytes;
- `retained_heap`: retained calculation status and the requested top objects.

Addresses are lowercase `0x`-prefixed hexadecimal strings because JSON numbers cannot represent
every unsigned 64-bit address exactly. Counts and byte sizes are non-negative JSON integers. Type
summaries are ordered by shallow bytes descending, object count descending, type name ascending,
then type address ascending. Local variables are ordered by name. Retained objects are ordered by
retained bytes descending.

`summary` sets `retained_heap.status` to `not_computed`, keeps `top_objects` empty, and emits `null`
for each thread's retained size. `retained-heap` sets the status to `complete` and includes at most
the requested `top_n` objects. Missing objects referenced by a frame have a `null` type name.

## Cross-language conformance

Every language implementation must verify:

1. valid and malformed artifact parsing;
2. graph behavior for chains, cycles, shared referents and multiple thread roots;
3. deterministic `summary` and `retained-heap` JSON against the shared golden corpus;
4. source SHA-256 and byte-size identity;
5. bounded failure on truncated or unsupported artifacts.

An implementation is interchangeable only when its normalized JSON matches the golden result and
its peak memory and runtime are measured on the repository's large-heap fixture.
