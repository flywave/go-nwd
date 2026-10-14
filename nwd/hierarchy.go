package nwd

import (
	"encoding/binary"
	"fmt"
)

// LogicalHierarchy is the decoded LcOpNwdLogicalHierarchy stream: the
// model browser tree (U19). Grammar (E2 LogicalHierarchyStreamLoaderImpl::
// parseStream@0xccf010, real-file verified findings N117):
//
//	[if the PartitionProps stream exists: i32 blockCount + blockCount×i32]
//	[u32 root marker]                        — root partition, vector slot 0
//	[u32 topChildCount][topChildCount × envelope]
//	[i32 tail flag]                          — !=0: RunPath links follow
//
// The PartitionProps block list is the U16 block↔tree-item mapping
// (getPartPropsBlocks@0xb30460).
type LogicalHierarchy struct {
	Blocks []uint32 `json:"partition_props_blocks,omitempty"`
	// Children are the top-level tree items under the partition root.
	Children []*TreeNode `json:"children"`
	// TailFlag is the trailing i32 (non-zero when RunPath links follow).
	TailFlag int32 `json:"tail_flag"`
	// Guids decodes LcOpGuidStore when provided (see DecodeGuidStore);
	// GuidIndexes on nodes index into this slice.
	Guids []string `json:"guids,omitempty"`

	Objects  int   `json:"objects"`
	MaxDepth int   `json:"max_depth"`
	Skipped  int   `json:"skipped_bytes"`
	Gaps     []Gap `json:"gaps,omitempty"`
	Complete bool  `json:"complete"`
}

// DecodeGuidStore decodes LcOpGuidStore (E2/E3 findings N118):
// [u32 1][u32 count][count × 16-byte GUID].
func DecodeGuidStore(stream []byte) ([]string, error) {
	if len(stream) < 8 {
		return nil, fmt.Errorf("nwd: guid store truncated (%d bytes)", len(stream))
	}
	if v := binary.LittleEndian.Uint32(stream); v != 1 {
		return nil, fmt.Errorf("nwd: guid store version %d != 1", v)
	}
	n := binary.LittleEndian.Uint32(stream[4:])
	if int(n)*16+8 > len(stream) {
		return nil, fmt.Errorf("nwd: guid store count %d exceeds stream", n)
	}
	out := make([]string, n)
	for i := uint32(0); i < n; i++ {
		b := stream[8+int(i)*16 : 8+int(i)*16+16]
		// Mixed-endian GUID text form (first three fields little-endian).
		out[i] = fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			binary.LittleEndian.Uint32(b[0:4]),
			binary.LittleEndian.Uint16(b[4:6]),
			binary.LittleEndian.Uint16(b[6:8]),
			b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
	}
	return out, nil
}

// DecodeLogicalHierarchy walks a LogicalHierarchy stream into a tree.
// The walk is tolerant: an unsupported or misaligned object records a Gap
// and resumes at the next plausible envelope marker (marker == expected
// next slot with a typeID <= 200), so one exotic node cannot hide the
// rest of the model tree.
func DecodeLogicalHierarchy(stream []byte, withPropsBlocks bool) (*LogicalHierarchy, error) {
	h := &LogicalHierarchy{}
	r := newBR(stream)
	if withPropsBlocks {
		n, err := r.i32()
		if err != nil {
			return nil, err
		}
		if n < 0 || n > 1<<20 {
			return nil, fmt.Errorf("nwd: logical hierarchy block count %d", n)
		}
		h.Blocks = make([]uint32, n)
		for i := range h.Blocks {
			v, err := r.i32()
			if err != nil {
				return nil, err
			}
			h.Blocks[i] = uint32(v)
		}
	}
	rootMarker, err := r.u32()
	if err != nil {
		return nil, err
	}
	if rootMarker != envNewBase {
		return nil, fmt.Errorf("nwd: logical hierarchy root marker %d != %d", rootMarker, envNewBase)
	}
	childCount, err := r.u32()
	if err != nil {
		return nil, err
	}
	if childCount > 1<<20 {
		return nil, fmt.Errorf("nwd: logical hierarchy child count %d", childCount)
	}

	or := &ObjectReader{r: r, FormatVersion: formatVersionGate, LogicalStream: true}
	// The root partition node occupies vector slot 0 via the stream-level
	// marker (addToObjectVector(root, 100)).
	or.vector = append(or.vector, ObjectRef{Kind: 2, Index: 0, TypeID: PartitionNode})

	for i := uint32(0); i < childCount && or.r.pos+8 <= len(stream); i++ {
		start := or.r.pos
		obj, err := or.ReadObject()
		if err != nil {
			// Tolerant top level: resync to the next plausible envelope
			// and keep walking; the skipped segment is reported as a gap.
			skip := or.resync()
			h.Gaps = append(h.Gaps, Gap{Pos: start, Skipped: skip, Err: err.Error()})
			if skip == 0 {
				break
			}
			continue
		}
		if obj == nil {
			continue
		}
		node := objToNode(obj)
		h.Children = append(h.Children, node)
		collectTreeStats(node, h)
	}
	tail, _ := r.i32()
	h.TailFlag = tail
	h.Complete = len(h.Gaps) == 0
	for _, g := range h.Gaps {
		h.Skipped += g.Skipped
	}
	return h, nil
}

func collectTreeStats(n *TreeNode, h *LogicalHierarchy) {
	h.Objects++
	depth := treeDepth(n, 1)
	if depth > h.MaxDepth {
		h.MaxDepth = depth
	}
	for _, c := range n.Children {
		collectTreeStats(c, h)
	}
}

func treeDepth(n *TreeNode, d int) int {
	max := d
	for _, c := range n.Children {
		if dd := treeDepth(c, d+1); dd > max {
			max = dd
		}
	}
	return max
}
