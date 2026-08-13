# Heap v1 input contract

Pydump Capture and all Pydump Analyzer implementations currently exchange the public PyHeap v1
binary artifact. Compatibility covers header flags, well-known types, thread frames and locals,
container content, referents, optional attributes and string representations, the type table, and
matching header/footer magic values.

The artifact must be complete before analysis starts. Every object type address must exist in the
type table, object addresses must be unique, indexed attribute names must refer to the declared
frequent-attribute table, and no bytes may follow the footer. A violation is a malformed artifact;
an analyzer must fail with context rather than invent missing facts.

PyHeap v1 is an input compatibility boundary, not the owner of Pydump's analysis output. Analyzer
implementations emit `pydump.analysis/v1` as defined in `analysis-v1.md`.
