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
// Derived from PyHeap's retained-heap implementation and ported to Pydump's
// compact Go graph.
package analysis

import (
	"sort"

	"github.com/compforge/pydump/analyzer/go/internal/heap"
)

type RetainedHeap struct {
	Objects []uint64          `json:"-"`
	Threads map[string]uint64 `json:"threads"`
}

type retainedCalculator struct {
	heap           *heap.Heap
	graph          *Graph
	subtreeRoots   []bool
	objectRetained []uint64
	threadRetained map[string]uint64
}

func CalculateRetainedHeap(value *heap.Heap) (*RetainedHeap, error) {
	graph, err := BuildGraph(value)
	if err != nil {
		return nil, err
	}
	calculator := retainedCalculator{
		heap:           value,
		graph:          graph,
		subtreeRoots:   make([]bool, graph.ObjectCount),
		objectRetained: make([]uint64, graph.ObjectCount),
		threadRetained: make(map[string]uint64, len(value.Threads)),
	}
	calculator.findStrictSubtrees()
	for object := uint32(0); object < graph.ObjectCount; object++ {
		calculator.objectRetained[object] = calculator.retainedForObject(object)
	}
	calculator.calculateThreads()
	return &RetainedHeap{calculator.objectRetained, calculator.threadRetained}, nil
}

func (c *retainedCalculator) findStrictSubtrees() {
	front := make(map[uint32]struct{})
	for address, object := range c.heap.Objects {
		index := uint32(address)
		if len(c.graph.ObjectReferents(index)) == 0 && c.graph.InboundCount(index) < 2 {
			c.subtreeRoots[index] = true
			c.objectRetained[index] = uint64(object.Size)
			for _, parent := range c.graph.InboundReferences(index) {
				front[parent] = struct{}{}
			}
		}
	}
	for {
		next := make(map[uint32]struct{})
		for current := range front {
			if c.graph.InboundCount(current) > 1 {
				continue
			}
			allSubtrees := true
			for _, referent := range c.graph.ObjectReferents(current) {
				if referent >= c.graph.ObjectCount || !c.subtreeRoots[referent] {
					allSubtrees = false
					break
				}
			}
			if !allSubtrees {
				next[current] = struct{}{}
				continue
			}
			c.subtreeRoots[current] = true
			retained := uint64(c.heap.Objects[current].Size)
			for _, referent := range c.graph.ObjectReferents(current) {
				retained += c.objectRetained[referent]
			}
			c.objectRetained[current] = retained
			for _, parent := range c.graph.InboundReferences(current) {
				next[parent] = struct{}{}
			}
		}
		if equalNodeSets(front, next) {
			return
		}
		front = next
	}
}

func (c *retainedCalculator) retainedForObject(object uint32) uint64 {
	return c.retained(map[uint32]int{object: 0}, []uint32{object}, true)
}

func (c *retainedCalculator) calculateThreads() {
	threadLocals := make([]map[uint64]struct{}, len(c.heap.Threads))
	for index, thread := range c.heap.Threads {
		threadLocals[index] = thread.LocalAddresses()
	}
	for removedIndex, removedThread := range c.heap.Threads {
		view := make(map[uint32]int, len(threadLocals[removedIndex]))
		front := make([]uint32, 0, len(threadLocals[removedIndex]))
		for address := range threadLocals[removedIndex] {
			node := c.graph.AddressIndex[address]
			count := c.graph.InboundCount(node)
			for otherIndex, locals := range threadLocals {
				if otherIndex == removedIndex {
					continue
				}
				if _, present := locals[address]; present {
					count++
				}
			}
			view[node] = count
			front = append(front, node)
		}
		c.threadRetained[removedThread.Name] = c.retained(view, front, false)
	}
}

func (c *retainedCalculator) retained(
	inboundView map[uint32]int,
	front []uint32,
	useSubtrees bool,
) uint64 {
	var result uint64
	deleted := make(map[uint32]struct{})
	for {
		sort.Slice(front, func(i, j int) bool { return inboundView[front[i]] > inboundView[front[j]] })
		var retained uint64
		var happened bool
		front, retained, happened = c.deleteUnreferenced(
			front,
			inboundView,
			deleted,
			useSubtrees,
		)
		if !happened {
			return result
		}
		result += retained
	}
}

func (c *retainedCalculator) deleteUnreferenced(
	front []uint32,
	inboundView map[uint32]int,
	deleted map[uint32]struct{},
	useSubtrees bool,
) ([]uint32, uint64, bool) {
	var retained uint64
	deletionHappened := false
	for index := len(front) - 1; index >= 0; index-- {
		current := front[index]
		if inboundView[current] > 0 {
			break
		}
		if _, alreadyDeleted := deleted[current]; alreadyDeleted {
			continue
		}
		front = append(front[:index], front[index+1:]...)
		deleted[current] = struct{}{}
		deletionHappened = true
		if useSubtrees && current < c.graph.ObjectCount && c.subtreeRoots[current] {
			retained += c.objectRetained[current]
			continue
		}
		if current >= c.graph.ObjectCount {
			continue
		}
		retained += uint64(c.heap.Objects[current].Size)
		for _, referent := range c.graph.ObjectReferents(current) {
			if _, wasDeleted := deleted[referent]; wasDeleted {
				continue
			}
			if count, present := inboundView[referent]; present {
				inboundView[referent] = count - 1
			} else {
				inboundView[referent] = c.graph.InboundCount(referent) - 1
			}
			front = append(front, referent)
		}
	}
	return front, retained, deletionHappened
}

func equalNodeSets(left, right map[uint32]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for item := range left {
		if _, ok := right[item]; !ok {
			return false
		}
	}
	return true
}
