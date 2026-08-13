package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/compforge/pydump/analyzer/go/internal/heap"
)

func TestRetainedHeapWithCacheReplacesCorruptCache(t *testing.T) {
	heapPath := filepath.Join(t.TempDir(), "heap.pyheap")
	if err := os.WriteFile(heapPath, []byte("heap contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheDirectory := t.TempDir()
	t.Setenv("PYHEAP_CACHE_DIR", cacheDirectory)
	cachePath, err := retainedCachePath(heapPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	retained, err := RetainedHeapWithCache(heapPath, cacheTestHeap())
	if err != nil {
		t.Fatal(err)
	}
	assertSizes(t, retained.Objects, []uint64{30, 20})

	file, err := os.Open(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var document cacheDocument
	if err := json.NewDecoder(file).Decode(&document); err != nil {
		t.Fatalf("replacement cache is invalid: %v", err)
	}
	if len(document.Objects) != 2 {
		t.Fatalf("cache has %d objects, want 2", len(document.Objects))
	}
	temporary, err := filepath.Glob(filepath.Join(cacheDirectory, ".*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temporary) != 0 {
		t.Fatalf("temporary cache files were not cleaned up: %v", temporary)
	}
}

func TestRetainedHeapWithCacheIgnoresCacheWriteFailure(t *testing.T) {
	heapPath := filepath.Join(t.TempDir(), "heap.pyheap")
	if err := os.WriteFile(heapPath, []byte("heap contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	blockedDirectory := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedDirectory, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PYHEAP_CACHE_DIR", blockedDirectory)

	retained, err := RetainedHeapWithCache(heapPath, cacheTestHeap())
	if err != nil {
		t.Fatal(err)
	}
	assertSizes(t, retained.Objects, []uint64{30, 20})
}

func cacheTestHeap() *heap.Heap {
	return testHeap([]heap.Object{
		{Address: 1, TypeAddress: 10, Size: 10, Referents: []uint64{2}},
		{Address: 2, TypeAddress: 10, Size: 20},
	})
}
