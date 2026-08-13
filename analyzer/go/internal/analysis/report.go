// Copyright 2022 Ivan Yurchenko
// Copyright 2026 CompForge
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Ported from Pydump's Python reference report implementation.
package analysis

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/compforge/pydump/analyzer/go/internal/heap"
)

const Schema = "pydump.analysis/v1"

type Report struct {
	Schema       string          `json:"schema"`
	Source       Source          `json:"source"`
	Heap         HeapSummary     `json:"heap"`
	Types        []TypeSummary   `json:"types"`
	Threads      []ThreadSummary `json:"threads"`
	RetainedHeap RetainedSummary `json:"retained_heap"`
}

type Source struct {
	SHA256                    string `json:"sha256"`
	SizeBytes                 int64  `json:"size_bytes"`
	HeapFormatVersion         uint32 `json:"heap_format_version"`
	CreatedAt                 string `json:"created_at"`
	WithStringRepresentations bool   `json:"with_string_representations"`
}

type HeapSummary struct {
	ObjectCount      int    `json:"object_count"`
	TypeCount        int    `json:"type_count"`
	ThreadCount      int    `json:"thread_count"`
	ReferentCount    uint64 `json:"referent_count"`
	ShallowSizeBytes uint64 `json:"shallow_size_bytes"`
}

type TypeSummary struct {
	TypeAddress      string `json:"type_address"`
	TypeName         string `json:"type_name"`
	ObjectCount      uint64 `json:"object_count"`
	ShallowSizeBytes uint64 `json:"shallow_size_bytes"`
	typeAddress      uint64
}

type ThreadSummary struct {
	Name              string         `json:"name"`
	IsAlive           bool           `json:"is_alive"`
	IsDaemon          bool           `json:"is_daemon"`
	RetainedSizeBytes *uint64        `json:"retained_size_bytes"`
	Frames            []FrameSummary `json:"frames"`
}

type FrameSummary struct {
	FileName       string         `json:"file_name"`
	LineNumber     uint32         `json:"line_number"`
	FunctionName   string         `json:"function_name"`
	LocalVariables []LocalSummary `json:"local_variables"`
}

type LocalSummary struct {
	Name          string  `json:"name"`
	ObjectAddress string  `json:"object_address"`
	TypeName      *string `json:"type_name"`
}

type RetainedSummary struct {
	Status     string           `json:"status"`
	TopN       int              `json:"top_n"`
	TopObjects []RetainedObject `json:"top_objects"`
}

type RetainedObject struct {
	ObjectAddress        string  `json:"object_address"`
	TypeName             string  `json:"type_name"`
	ShallowSizeBytes     uint32  `json:"shallow_size_bytes"`
	RetainedSizeBytes    uint64  `json:"retained_size_bytes"`
	StringRepresentation *string `json:"string_representation"`
}

func BuildReport(path string, value *heap.Heap, retained *RetainedHeap, topN int) (*Report, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open heap for source identity: %w", err)
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("hash heap: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close heap after hashing: %w", err)
	}
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat heap: %w", err)
	}

	var referentCount uint64
	var shallowSize uint64
	for _, object := range value.Objects {
		referentCount += uint64(len(object.Referents))
		shallowSize += uint64(object.Size)
	}
	report := &Report{
		Schema: Schema,
		Source: Source{
			SHA256:                    fmt.Sprintf("%x", digest.Sum(nil)),
			SizeBytes:                 stat.Size(),
			HeapFormatVersion:         value.Header.Version,
			CreatedAt:                 value.Header.CreatedAt,
			WithStringRepresentations: value.Header.WithStringRepr,
		},
		Heap: HeapSummary{
			ObjectCount:      len(value.Objects),
			TypeCount:        len(value.Types),
			ThreadCount:      len(value.Threads),
			ReferentCount:    referentCount,
			ShallowSizeBytes: shallowSize,
		},
		Types:   typeSummaries(value),
		Threads: threadSummaries(value, retained),
		RetainedHeap: RetainedSummary{
			Status:     "not_computed",
			TopN:       topN,
			TopObjects: []RetainedObject{},
		},
	}
	if retained != nil {
		report.RetainedHeap.Status = "complete"
		report.RetainedHeap.TopObjects, err = retainedObjects(value, retained, topN)
		if err != nil {
			return nil, err
		}
	}
	return report, nil
}

func typeSummaries(value *heap.Heap) []TypeSummary {
	byType := make(map[uint64]*TypeSummary)
	for _, object := range value.Objects {
		summary := byType[object.TypeAddress]
		if summary == nil {
			summary = &TypeSummary{
				TypeAddress: address(object.TypeAddress),
				TypeName:    value.Types[object.TypeAddress],
				typeAddress: object.TypeAddress,
			}
			byType[object.TypeAddress] = summary
		}
		summary.ObjectCount++
		summary.ShallowSizeBytes += uint64(object.Size)
	}
	result := make([]TypeSummary, 0, len(byType))
	for _, summary := range byType {
		result = append(result, *summary)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i], result[j]
		if left.ShallowSizeBytes != right.ShallowSizeBytes {
			return left.ShallowSizeBytes > right.ShallowSizeBytes
		}
		if left.ObjectCount != right.ObjectCount {
			return left.ObjectCount > right.ObjectCount
		}
		if left.TypeName != right.TypeName {
			return left.TypeName < right.TypeName
		}
		return left.typeAddress < right.typeAddress
	})
	return result
}

func threadSummaries(value *heap.Heap, retained *RetainedHeap) []ThreadSummary {
	result := make([]ThreadSummary, 0, len(value.Threads))
	for _, thread := range value.Threads {
		frames := make([]FrameSummary, 0, len(thread.StackTrace))
		for _, frame := range thread.StackTrace {
			names := make([]string, 0, len(frame.Locals))
			for name := range frame.Locals {
				names = append(names, name)
			}
			sort.Strings(names)
			locals := make([]LocalSummary, 0, len(names))
			for _, name := range names {
				objectAddress := frame.Locals[name]
				var typeName *string
				if objectIndex, ok := value.ObjectByAddress[objectAddress]; ok {
					name := value.Types[value.Objects[objectIndex].TypeAddress]
					typeName = &name
				}
				locals = append(locals, LocalSummary{name, address(objectAddress), typeName})
			}
			frames = append(frames, FrameSummary{
				FileName:       frame.FileName,
				LineNumber:     frame.LineNumber,
				FunctionName:   frame.FunctionName,
				LocalVariables: locals,
			})
		}
		var retainedBytes *uint64
		if retained != nil {
			value := retained.Threads[thread.Name]
			retainedBytes = &value
		}
		result = append(result, ThreadSummary{
			Name:              thread.Name,
			IsAlive:           thread.IsAlive,
			IsDaemon:          thread.IsDaemon,
			RetainedSizeBytes: retainedBytes,
			Frames:            frames,
		})
	}
	return result
}

func retainedObjects(value *heap.Heap, retained *RetainedHeap, topN int) ([]RetainedObject, error) {
	indexes := make([]int, len(value.Objects))
	for index := range indexes {
		indexes[index] = index
	}
	sort.SliceStable(indexes, func(i, j int) bool {
		return retained.Objects[indexes[i]] > retained.Objects[indexes[j]]
	})
	if topN < len(indexes) {
		indexes = indexes[:topN]
	}
	result := make([]RetainedObject, 0, len(indexes))
	for _, index := range indexes {
		object := value.Objects[index]
		var representation *string
		if value.Header.WithStringRepr {
			text, err := value.StringRepresentation(object.Address)
			if err != nil {
				return nil, err
			}
			representation = &text
		}
		result = append(result, RetainedObject{
			ObjectAddress:        address(object.Address),
			TypeName:             value.Types[object.TypeAddress],
			ShallowSizeBytes:     object.Size,
			RetainedSizeBytes:    retained.Objects[index],
			StringRepresentation: representation,
		})
	}
	return result, nil
}

func address(value uint64) string {
	return fmt.Sprintf("0x%x", value)
}
