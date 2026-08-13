package analysis

import (
	"fmt"

	"github.com/compforge/pydump/analyzer/go/internal/heap"
)

// Graph interns 64-bit process addresses into compact uint32 node indexes. Object
// nodes keep their Heap.Objects index; dangling referents follow them.
type Graph struct {
	ObjectCount   uint32
	AddressIndex  map[uint64]uint32
	RefOffsets    []uint64
	Referents     []uint32
	InboundOffset []uint64
	Inbound       []uint32
}

func BuildGraph(value *heap.Heap) (*Graph, error) {
	if uint64(len(value.Objects)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("heap has too many objects for uint32 graph indexes: %d", len(value.Objects))
	}
	index := make(map[uint64]uint32, len(value.Objects))
	for objectIndex, object := range value.Objects {
		index[object.Address] = uint32(objectIndex)
	}
	addAddress := func(address uint64) error {
		if _, ok := index[address]; ok {
			return nil
		}
		if uint64(len(index)) > uint64(^uint32(0)) {
			return fmt.Errorf("heap graph has too many address nodes")
		}
		index[address] = uint32(len(index))
		return nil
	}
	for _, object := range value.Objects {
		for _, address := range object.Referents {
			if err := addAddress(address); err != nil {
				return nil, err
			}
		}
	}
	for _, thread := range value.Threads {
		for address := range thread.LocalAddresses() {
			if err := addAddress(address); err != nil {
				return nil, err
			}
		}
	}

	refOffsets := make([]uint64, len(value.Objects)+1)
	for objectIndex, object := range value.Objects {
		refOffsets[objectIndex+1] = refOffsets[objectIndex] + uint64(len(object.Referents))
	}
	referents := make([]uint32, refOffsets[len(refOffsets)-1])
	inboundCount := make([]uint32, len(index))
	for objectIndex, object := range value.Objects {
		start := refOffsets[objectIndex]
		for edgeIndex, address := range object.Referents {
			referent := index[address]
			referents[start+uint64(edgeIndex)] = referent
			inboundCount[referent]++
		}
	}
	inboundOffsets := make([]uint64, len(index)+1)
	for node, count := range inboundCount {
		inboundOffsets[node+1] = inboundOffsets[node] + uint64(count)
	}
	inbound := make([]uint32, inboundOffsets[len(inboundOffsets)-1])
	cursor := append([]uint64(nil), inboundOffsets[:len(inboundOffsets)-1]...)
	for source := range value.Objects {
		for _, target := range referents[refOffsets[source]:refOffsets[source+1]] {
			inbound[cursor[target]] = uint32(source)
			cursor[target]++
		}
	}
	return &Graph{
		ObjectCount:   uint32(len(value.Objects)),
		AddressIndex:  index,
		RefOffsets:    refOffsets,
		Referents:     referents,
		InboundOffset: inboundOffsets,
		Inbound:       inbound,
	}, nil
}

func (g *Graph) ObjectReferents(object uint32) []uint32 {
	return g.Referents[g.RefOffsets[object]:g.RefOffsets[object+1]]
}

func (g *Graph) InboundReferences(node uint32) []uint32 {
	return g.Inbound[g.InboundOffset[node]:g.InboundOffset[node+1]]
}

func (g *Graph) InboundCount(node uint32) int {
	return int(g.InboundOffset[node+1] - g.InboundOffset[node])
}
