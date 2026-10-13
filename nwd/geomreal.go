package nwd

import (
	"encoding/binary"
	"math"
)

// VertexBlock is one geometry element found in the geometry stream.
type VertexBlock struct {
	ElementType int          `json:"element_type"` // 94 TriangleSetElem, 95 LineSetElem, 96 PointSetElem
	VertexCount int          `json:"vertex_count"`
	Vertices    [][3]float64 `json:"vertices,omitempty"`
	IndexCount  int          `json:"index_count,omitempty"`
}

// DecodeGeometryVertices inflates the Geometry logical stream and extracts
// every VertexSet(60) object as a geometry block
// (OdNwGraphicVertexSetReader::readElement@0xc26590, readVertices@0xc26e80).
//
// Each geometry block is an envelope run starting at marker 100 (element type
// 94/95/96); its first child is the VertexSet at marker+8 (marker 101, type 60).
// The VertexSet body is:
//
//	[i32 vertexCount][i32 floatCount][floatCount * f32]
//	[optional index table (decodeIndexTable) when floatCount/3 < vertexCount]
//
// When floatCount == 3*vertexCount the floats are the vertices directly (the
// non-deduplicated sample, e.g. FormatVersionEx 451). When floatCount/3 is
// smaller, the floats form a shared position pool and vertexCount indices are
// reconstructed from the index table (the compressed/deduplicated sample,
// e.g. FormatVersionEx 431 - findings N68/N71).
func DecodeGeometryVertices(stream []byte, limit int) ([]VertexBlock, error) {
	n := len(stream)
	var blocks []VertexBlock
	for pos := 0; pos+24 <= n; pos++ {
		if binary.LittleEndian.Uint32(stream[pos:]) != uint32(envNewBase) {
			continue
		}
		t := int(binary.LittleEndian.Uint32(stream[pos+4:]))
		if t != 94 && t != 95 && t != 96 {
			continue
		}
		vs := pos + 8
		if vs+16 > n {
			break
		}
		if binary.LittleEndian.Uint32(stream[vs:]) != uint32(envNewBase+1) ||
			binary.LittleEndian.Uint32(stream[vs+4:]) != 60 {
			continue
		}
		vc := int32(binary.LittleEndian.Uint32(stream[vs+8:]))
		fc := int32(binary.LittleEndian.Uint32(stream[vs+12:]))
		if vc <= 0 || vc > 50_000_000 || fc < 3 || fc%3 != 0 {
			continue
		}
		start := vs + 16
		end := start + int(fc)*4
		if end > n {
			break
		}
		pool := make([][3]float64, 0, fc/3)
		for i := 0; i < int(fc)/3; i++ {
			o := start + i*12
			pool = append(pool, [3]float64{
				float64(f32at(stream, o)),
				float64(f32at(stream, o+4)),
				float64(f32at(stream, o+8)),
			})
		}

		var verts [][3]float64
		idxCount := 0
		if fc/3 == vc {
			verts = pool
		} else {
			idx, _, err := DecodeIndexTable(stream, end, int(vc))
			if err != nil {
				// Malformed / not a real VertexSet: skip the candidate.
				continue
			}
			idxCount = len(idx)
			verts = make([][3]float64, 0, len(idx))
			ok := true
			for _, k := range idx {
				if int(k) >= len(pool) {
					ok = false
					break
				}
				verts = append(verts, pool[k])
			}
			if !ok || len(verts) == 0 {
				continue
			}
		}
		blocks = append(blocks, VertexBlock{
			ElementType: t,
			VertexCount: len(verts),
			Vertices:    verts,
			IndexCount:  idxCount,
		})
		if limit > 0 && len(blocks) >= limit {
			break
		}
	}
	return blocks, nil
}

func f32at(b []byte, o int) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(b[o:]))
}
