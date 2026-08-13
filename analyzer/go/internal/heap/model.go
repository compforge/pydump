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
// Derived from PyHeap's heap model and modified for Pydump's Go analyzer.
package heap

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

type ContentKind uint8

const (
	ContentNone ContentKind = iota
	ContentDict
	ContentList
	ContentSet
	ContentTuple
)

type Header struct {
	Version        uint32
	CreatedAt      string
	WithStringRepr bool
	WellKnownTypes map[string]uint64
}

type ThreadFrame struct {
	FileName     string
	LineNumber   uint32
	FunctionName string
	Locals       map[string]uint64
}

type Thread struct {
	Name       string
	IsAlive    bool
	IsDaemon   bool
	StackTrace []ThreadFrame
}

func (t Thread) LocalAddresses() map[uint64]struct{} {
	result := make(map[uint64]struct{})
	for _, frame := range t.StackTrace {
		for _, address := range frame.Locals {
			result[address] = struct{}{}
		}
	}
	return result
}

type DictEntry struct {
	Key   uint64
	Value uint64
}

type Object struct {
	Address      uint64
	TypeAddress  uint64
	Size         uint32
	Referents    []uint64
	ContentKind  ContentKind
	Sequence     []uint64
	Dict         []DictEntry
	StringOffset int64
}

type Heap struct {
	Path            string
	Header          Header
	Threads         []Thread
	Objects         []Object
	ObjectByAddress map[uint64]uint32
	Types           map[uint64]string
	source          *os.File
}

func (h *Heap) Close() error {
	if h.source == nil {
		return nil
	}
	err := h.source.Close()
	h.source = nil
	return err
}

func (h *Heap) StringRepresentation(address uint64) (string, error) {
	if !h.Header.WithStringRepr {
		return "", nil
	}
	return h.stringRepresentation(address, make(map[uint64]struct{}))
}

func (h *Heap) stringRepresentation(address uint64, seen map[uint64]struct{}) (string, error) {
	index, ok := h.ObjectByAddress[address]
	if !ok {
		return "(unknown)", nil
	}
	object := h.Objects[index]
	if object.ContentKind == ContentNone {
		return h.readStringAt(object.StringOffset)
	}

	left, right := containerBrackets(object.ContentKind)
	if _, found := seen[address]; found {
		return left + "..." + right, nil
	}
	nested := make(map[uint64]struct{}, len(seen)+1)
	for item := range seen {
		nested[item] = struct{}{}
	}
	nested[address] = struct{}{}

	parts := make([]string, 0, len(object.Sequence)+len(object.Dict))
	if object.ContentKind == ContentDict {
		for _, entry := range object.Dict {
			key, err := h.stringRepresentation(entry.Key, nested)
			if err != nil {
				return "", err
			}
			value, err := h.stringRepresentation(entry.Value, nested)
			if err != nil {
				return "", err
			}
			parts = append(parts, key+": "+value)
		}
	} else {
		for _, item := range object.Sequence {
			value, err := h.stringRepresentation(item, nested)
			if err != nil {
				return "", err
			}
			parts = append(parts, value)
		}
	}
	return left + strings.Join(parts, ", ") + right, nil
}

func (h *Heap) readStringAt(offset int64) (string, error) {
	if h.source == nil || offset < 0 {
		return "", nil
	}
	var lengthBytes [2]byte
	if _, err := h.source.ReadAt(lengthBytes[:], offset); err != nil {
		return "", fmt.Errorf("read string length at offset %d: %w", offset, err)
	}
	value := make([]byte, binary.BigEndian.Uint16(lengthBytes[:]))
	read, err := h.source.ReadAt(value, offset+2)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read string at offset %d: %w", offset, err)
	}
	if read != len(value) {
		return "", fmt.Errorf("truncated string at offset %d: read %d of %d bytes", offset, read, len(value))
	}
	return decodeUTF8BackslashReplace(value), nil
}

func decodeUTF8BackslashReplace(value []byte) string {
	var result strings.Builder
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&result, "\\x%02x", value[0])
			value = value[1:]
			continue
		}
		result.WriteRune(r)
		value = value[size:]
	}
	return result.String()
}

func containerBrackets(kind ContentKind) (string, string) {
	switch kind {
	case ContentList:
		return "[", "]"
	case ContentTuple:
		return "(", ")"
	default:
		return "{", "}"
	}
}
