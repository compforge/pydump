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
// Derived from PyHeap's HeapReader and rewritten as a streaming PyHeap v1
// reader for Pydump's Go analyzer.
package heap

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
)

const (
	magic              = uint64(123_000_321)
	formatVersion      = uint32(1)
	flagWithStringRepr = uint64(1)
)

type reader struct {
	input  *bufio.Reader
	offset int64
}

func Load(path string) (*Heap, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open heap %q: %w", path, err)
	}
	r := &reader{input: bufio.NewReaderSize(file, 256*1024)}
	result, err := r.read(path, file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return result, nil
}

func (r *reader) read(path string, source *os.File) (*Heap, error) {
	start, err := r.u64()
	if err != nil {
		return nil, err
	}
	if start != magic {
		return nil, fmt.Errorf("invalid PyHeap magic value: %d", start)
	}
	version, err := r.u32()
	if err != nil {
		return nil, err
	}
	if version != formatVersion {
		return nil, fmt.Errorf("unsupported PyHeap format version: %d", version)
	}
	createdAt, err := r.longString()
	if err != nil {
		return nil, err
	}
	flags, err := r.u64()
	if err != nil {
		return nil, err
	}
	wellKnown, err := r.stringAddressMap()
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"dict", "list", "set", "tuple"} {
		if _, ok := wellKnown[name]; !ok {
			return nil, fmt.Errorf("PyHeap header is missing well-known type %q", name)
		}
	}
	header := Header{
		Version:        version,
		CreatedAt:      createdAt,
		WithStringRepr: flags&flagWithStringRepr != 0,
		WellKnownTypes: wellKnown,
	}

	threads, err := r.threads()
	if err != nil {
		return nil, err
	}
	frequent, err := r.stringList()
	if err != nil {
		return nil, err
	}
	commonTypes, err := r.commonTypes(frequent)
	if err != nil {
		return nil, err
	}
	objects, byAddress, err := r.objects(header, frequent, commonTypes)
	if err != nil {
		return nil, err
	}
	types, err := r.addressStringMap()
	if err != nil {
		return nil, err
	}
	end, err := r.u64()
	if err != nil {
		return nil, err
	}
	if end != magic {
		return nil, fmt.Errorf("invalid PyHeap footer magic value: %d", end)
	}
	if _, err := r.input.ReadByte(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected data after PyHeap footer")
		}
		return nil, fmt.Errorf("read after PyHeap footer: %w", err)
	}
	for _, object := range objects {
		if _, ok := types[object.TypeAddress]; !ok {
			return nil, fmt.Errorf(
				"PyHeap type table is missing address 0x%x for object 0x%x",
				object.TypeAddress,
				object.Address,
			)
		}
	}
	return &Heap{
		Path:            path,
		Header:          header,
		Threads:         threads,
		Objects:         objects,
		ObjectByAddress: byAddress,
		Types:           types,
		source:          source,
	}, nil
}

func (r *reader) threads() ([]Thread, error) {
	count, err := r.u32()
	if err != nil {
		return nil, err
	}
	result := make([]Thread, 0, count)
	for range count {
		name, err := r.longString()
		if err != nil {
			return nil, err
		}
		alive, err := r.boolean()
		if err != nil {
			return nil, err
		}
		daemon, err := r.boolean()
		if err != nil {
			return nil, err
		}
		frameCount, err := r.u32()
		if err != nil {
			return nil, err
		}
		frames := make([]ThreadFrame, 0, frameCount)
		for range frameCount {
			fileName, err := r.longString()
			if err != nil {
				return nil, err
			}
			line, err := r.u32()
			if err != nil {
				return nil, err
			}
			function, err := r.longString()
			if err != nil {
				return nil, err
			}
			localCount, err := r.u32()
			if err != nil {
				return nil, err
			}
			locals := make(map[string]uint64, localCount)
			for range localCount {
				localName, err := r.longString()
				if err != nil {
					return nil, err
				}
				address, err := r.u64()
				if err != nil {
					return nil, err
				}
				locals[localName] = address
			}
			frames = append(frames, ThreadFrame{fileName, line, function, locals})
		}
		result = append(result, Thread{name, alive, daemon, frames})
	}
	return result, nil
}

func (r *reader) commonTypes(frequent []string) (map[uint64]struct{}, error) {
	count, err := r.u32()
	if err != nil {
		return nil, err
	}
	result := make(map[uint64]struct{}, count)
	for range count {
		address, err := r.u64()
		if err != nil {
			return nil, err
		}
		result[address] = struct{}{}
		attributeCount, err := r.u32()
		if err != nil {
			return nil, err
		}
		for range attributeCount {
			if _, err := r.attributeName(frequent); err != nil {
				return nil, err
			}
			if _, err := r.u64(); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

func (r *reader) objects(
	header Header,
	frequent []string,
	commonTypes map[uint64]struct{},
) ([]Object, map[uint64]uint32, error) {
	count, err := r.u32()
	if err != nil {
		return nil, nil, err
	}
	result := make([]Object, 0, count)
	byAddress := make(map[uint64]uint32, count)
	known := header.WellKnownTypes
	containerTypes := map[uint64]struct{}{
		known["dict"]:  {},
		known["list"]:  {},
		known["set"]:   {},
		known["tuple"]: {},
	}

	for range count {
		address, err := r.u64()
		if err != nil {
			return nil, nil, err
		}
		typeAddress, err := r.u64()
		if err != nil {
			return nil, nil, err
		}
		size, err := r.u32()
		if err != nil {
			return nil, nil, err
		}
		kind, sequence, dictionary, contentReferents, err := r.content(typeAddress, known)
		if err != nil {
			return nil, nil, err
		}
		extra, err := r.addresses()
		if err != nil {
			return nil, nil, err
		}
		referents := uniqueSorted(append(extra, contentReferents...))

		if _, common := commonTypes[typeAddress]; !common {
			attributeCount, err := r.u32()
			if err != nil {
				return nil, nil, err
			}
			for range attributeCount {
				if _, err := r.attributeName(frequent); err != nil {
					return nil, nil, err
				}
				if _, err := r.u64(); err != nil {
					return nil, nil, err
				}
			}
		}

		stringOffset := int64(-1)
		if _, container := containerTypes[typeAddress]; header.WithStringRepr && !container {
			stringOffset = r.offset
			if err := r.skipLongString(); err != nil {
				return nil, nil, err
			}
		}
		if _, duplicate := byAddress[address]; duplicate {
			return nil, nil, fmt.Errorf("duplicate object address 0x%x", address)
		}
		byAddress[address] = uint32(len(result))
		result = append(result, Object{
			Address:      address,
			TypeAddress:  typeAddress,
			Size:         size,
			Referents:    referents,
			ContentKind:  kind,
			Sequence:     sequence,
			Dict:         dictionary,
			StringOffset: stringOffset,
		})
	}
	return result, byAddress, nil
}

func (r *reader) content(
	typeAddress uint64,
	known map[string]uint64,
) (ContentKind, []uint64, []DictEntry, []uint64, error) {
	if typeAddress == known["dict"] {
		count, err := r.u32()
		if err != nil {
			return 0, nil, nil, nil, err
		}
		entries := make([]DictEntry, 0, count)
		referents := make([]uint64, 0, count*2)
		for range count {
			key, err := r.u64()
			if err != nil {
				return 0, nil, nil, nil, err
			}
			value, err := r.u64()
			if err != nil {
				return 0, nil, nil, nil, err
			}
			entries = append(entries, DictEntry{key, value})
			referents = append(referents, key, value)
		}
		return ContentDict, nil, entries, referents, nil
	}
	if typeAddress == known["list"] || typeAddress == known["set"] || typeAddress == known["tuple"] {
		values, err := r.addresses()
		if err != nil {
			return 0, nil, nil, nil, err
		}
		kind := ContentList
		if typeAddress == known["set"] {
			kind = ContentSet
			values = uniqueSorted(values)
		} else if typeAddress == known["tuple"] {
			kind = ContentTuple
		}
		return kind, values, nil, values, nil
	}
	return ContentNone, nil, nil, nil, nil
}

func uniqueSorted(values []uint64) []uint64 {
	if len(values) == 0 {
		return nil
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func (r *reader) stringAddressMap() (map[string]uint64, error) {
	count, err := r.u32()
	if err != nil {
		return nil, err
	}
	result := make(map[string]uint64, count)
	for range count {
		name, err := r.longString()
		if err != nil {
			return nil, err
		}
		address, err := r.u64()
		if err != nil {
			return nil, err
		}
		result[name] = address
	}
	return result, nil
}

func (r *reader) addressStringMap() (map[uint64]string, error) {
	count, err := r.u32()
	if err != nil {
		return nil, err
	}
	result := make(map[uint64]string, count)
	for range count {
		address, err := r.u64()
		if err != nil {
			return nil, err
		}
		name, err := r.longString()
		if err != nil {
			return nil, err
		}
		result[address] = name
	}
	return result, nil
}

func (r *reader) stringList() ([]string, error) {
	count, err := r.u32()
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, count)
	for range count {
		value, err := r.longString()
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

func (r *reader) addresses() ([]uint64, error) {
	count, err := r.u32()
	if err != nil {
		return nil, err
	}
	result := make([]uint64, 0, count)
	for range count {
		address, err := r.u64()
		if err != nil {
			return nil, err
		}
		result = append(result, address)
	}
	return result, nil
}

func (r *reader) attributeName(frequent []string) (string, error) {
	lengthOrIndex, err := r.i16()
	if err != nil {
		return "", err
	}
	if lengthOrIndex >= 0 {
		return r.string(uint16(lengthOrIndex))
	}
	index := -int(lengthOrIndex + 1)
	if index >= len(frequent) {
		return "", fmt.Errorf("invalid frequent attribute index: %d", index)
	}
	return frequent[index], nil
}

func (r *reader) skipLongString() error {
	length, err := r.u16()
	if err != nil {
		return err
	}
	if _, err := io.CopyN(io.Discard, r.input, int64(length)); err != nil {
		return fmt.Errorf("truncated PyHeap data at offset %d: %w", r.offset, err)
	}
	r.offset += int64(length)
	return nil
}

func (r *reader) longString() (string, error) {
	length, err := r.u16()
	if err != nil {
		return "", err
	}
	return r.string(length)
}

func (r *reader) string(length uint16) (string, error) {
	value := make([]byte, length)
	if err := r.readExact(value); err != nil {
		return "", err
	}
	return decodeUTF8BackslashReplace(value), nil
}

func (r *reader) boolean() (bool, error) {
	var value [1]byte
	if err := r.readExact(value[:]); err != nil {
		return false, err
	}
	return value[0] != 0, nil
}

func (r *reader) i16() (int16, error) {
	value, err := r.u16()
	return int16(value), err
}

func (r *reader) u16() (uint16, error) {
	var value [2]byte
	if err := r.readExact(value[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value[:]), nil
}

func (r *reader) u32() (uint32, error) {
	var value [4]byte
	if err := r.readExact(value[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(value[:]), nil
}

func (r *reader) u64() (uint64, error) {
	var value [8]byte
	if err := r.readExact(value[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(value[:]), nil
}

func (r *reader) readExact(value []byte) error {
	if _, err := io.ReadFull(r.input, value); err != nil {
		return fmt.Errorf("truncated PyHeap data at offset %d: %w", r.offset, err)
	}
	r.offset += int64(len(value))
	return nil
}
