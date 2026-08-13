package analysis

import (
	"testing"

	"github.com/compforge/pydump/analyzer/go/internal/heap"
)

func TestRetainedHeapHandlesChainsAndCycles(t *testing.T) {
	chain := testHeap([]heap.Object{
		{Address: 1, TypeAddress: 10, Size: 10, Referents: []uint64{2}},
		{Address: 2, TypeAddress: 10, Size: 20, Referents: []uint64{3}},
		{Address: 3, TypeAddress: 10, Size: 30},
	})
	cycle := testHeap([]heap.Object{
		{Address: 1, TypeAddress: 10, Size: 10, Referents: []uint64{2}},
		{Address: 2, TypeAddress: 10, Size: 20, Referents: []uint64{1}},
	})

	chainRetained, err := CalculateRetainedHeap(chain)
	if err != nil {
		t.Fatal(err)
	}
	cycleRetained, err := CalculateRetainedHeap(cycle)
	if err != nil {
		t.Fatal(err)
	}
	assertSizes(t, chainRetained.Objects, []uint64{60, 50, 30})
	assertSizes(t, cycleRetained.Objects, []uint64{30, 30})
}

func TestRetainedHeapPreservesSharedReferents(t *testing.T) {
	value := testHeap([]heap.Object{
		{Address: 1, TypeAddress: 10, Size: 10, Referents: []uint64{2}},
		{Address: 2, TypeAddress: 10, Size: 20},
		{Address: 3, TypeAddress: 10, Size: 30, Referents: []uint64{2}},
	})

	retained, err := CalculateRetainedHeap(value)
	if err != nil {
		t.Fatal(err)
	}
	assertSizes(t, retained.Objects, []uint64{10, 20, 30})
}

func testHeap(objects []heap.Object) *heap.Heap {
	byAddress := make(map[uint64]uint32, len(objects))
	for index, object := range objects {
		byAddress[object.Address] = uint32(index)
	}
	return &heap.Heap{
		Objects:         objects,
		ObjectByAddress: byAddress,
		Types:           map[uint64]string{10: "object"},
	}
}

func assertSizes(t *testing.T, actual, expected []uint64) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("got %d sizes, want %d", len(actual), len(expected))
	}
	for index := range expected {
		if actual[index] != expected[index] {
			t.Fatalf("size[%d] = %d, want %d", index, actual[index], expected[index])
		}
	}
}
