package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/compforge/pydump/analyzer/go/internal/heap"
)

func TestSharedContractFixtureMatchesGoImplementation(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	heapPath := filepath.Join(root, "contracts", "testdata", "heap-v1.pyheap")
	expectedPath := filepath.Join(root, "contracts", "testdata", "analysis-v1.expected.json")
	value, err := heap.Load(heapPath)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	retained, err := CalculateRetainedHeap(value)
	if err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport(heapPath, value, retained, 8)
	if err != nil {
		t.Fatal(err)
	}
	actualJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	var actual, expected any
	if err := json.Unmarshal(actualJSON, &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(expectedJSON, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Go analysis does not match shared contract\nactual: %s\nexpected: %s", actualJSON, expectedJSON)
	}
}
