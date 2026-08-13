package analysis

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/compforge/pydump/analyzer/go/internal/heap"
)

const cacheVersion = 1

type cacheDocument struct {
	Objects map[string]uint64 `json:"objects"`
	Threads map[string]uint64 `json:"threads"`
}

func RetainedHeapWithCache(path string, value *heap.Heap) (*RetainedHeap, error) {
	cachePath, err := retainedCachePath(path)
	if err != nil {
		return nil, err
	}
	retained, err := loadRetainedCache(cachePath, value)
	if err != nil {
		return nil, err
	}
	if retained != nil {
		return retained, nil
	}
	retained, err = CalculateRetainedHeap(value)
	if err != nil {
		return nil, err
	}
	if err := storeRetainedCache(cachePath, value, retained); err != nil {
		return nil, err
	}
	return retained, nil
}

func retainedCachePath(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open heap for retained cache identity: %w", err)
	}
	digest := sha1.New()
	if _, err := io.Copy(digest, file); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("hash heap for retained cache: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close heap after retained cache hash: %w", err)
	}
	name := fmt.Sprintf("%s.%x.%d.retained_heap", filepath.Base(path), digest.Sum(nil), cacheVersion)
	if directory := os.Getenv("PYHEAP_CACHE_DIR"); directory != "" {
		return filepath.Join(directory, name), nil
	}
	return path + fmt.Sprintf(".%x.%d.retained_heap", digest.Sum(nil), cacheVersion), nil
}

func loadRetainedCache(path string, value *heap.Heap) (*RetainedHeap, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open retained cache: %w", err)
	}
	defer file.Close()
	var document cacheDocument
	if err := json.NewDecoder(file).Decode(&document); err != nil {
		return nil, fmt.Errorf("decode retained cache: %w", err)
	}
	objects := make([]uint64, len(value.Objects))
	for addressText, retained := range document.Objects {
		address, err := strconv.ParseUint(addressText, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("decode retained cache object address %q: %w", addressText, err)
		}
		index, ok := value.ObjectByAddress[address]
		if !ok {
			return nil, fmt.Errorf("retained cache contains unknown object 0x%x", address)
		}
		objects[index] = retained
	}
	if len(document.Objects) != len(value.Objects) {
		return nil, fmt.Errorf("retained cache has %d objects, expected %d", len(document.Objects), len(value.Objects))
	}
	return &RetainedHeap{Objects: objects, Threads: document.Threads}, nil
}

func storeRetainedCache(path string, value *heap.Heap, retained *RetainedHeap) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create retained cache directory: %w", err)
	}
	document := cacheDocument{
		Objects: make(map[string]uint64, len(value.Objects)),
		Threads: retained.Threads,
	}
	for index, object := range value.Objects {
		document.Objects[strconv.FormatUint(object.Address, 10)] = retained.Objects[index]
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create retained cache: %w", err)
	}
	if err := json.NewEncoder(file).Encode(document); err != nil {
		_ = file.Close()
		return fmt.Errorf("encode retained cache: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close retained cache: %w", err)
	}
	return nil
}
