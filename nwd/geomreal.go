package nwd

import (
	"fmt"
)

// VertexBlock is one geometry element found in the geometry stream.
type VertexBlock struct {
	ElementType int          `json:"element_type"` // 94 TriangleSetElem, 95 LineSetElem, 96 PointSetElem
	VertexCount int          `json:"vertex_count"`
	Vertices    [][3]float64 `json:"vertices,omitempty"`
}

// DecodeGeometryVertices inflates the Geometry logical stream and extracts
// every VertexSet(60) object as a geometry block (findings N47/N48). The
// stream is a sequence of geometry blocks, each an object envelope run
// starting at marker 100 (element) with marker 101 / typeID 60 (VertexSet)
// and marker 102 (NormalSet/ColorSet). VertexSet payload =
// [i32 vertexCount][i32 floatCount=vertexCount*3][f32 x,y,z ...].
//
// Triangle/line/point indices are stored in quantized sets not yet decoded
// (U21); this extracts the real vertex geometry.
func DecodeGeometryVertices(stream []byte, limit int) ([]VertexBlock, error) {
	r := newBR(stream)
	var blocks []VertexBlock
	elemType := 0
	for {
		if limit > 0 && len(blocks) >= limit {
			break
		}
		if !resyncToMarker(r, envNewBase) {
			break
		}
		// Element envelope: marker 100 + typeID.
		if r.pos+8 > len(stream) {
			break
		}
		r.pos += 4
		t, err := r.u32()
		if err != nil {
			break
		}
		switch int(t) {
		case 94, 95, 96:
			elemType = int(t)
		default:
			// Not an element start; skip one byte to keep scanning.
			r.pos -= 3
			continue
		}
		// Expect marker 101 / typeID 60 VertexSet.
		if !resyncToMarker(r, envNewBase+1) {
			break
		}
		if r.pos+8 > len(stream) {
			break
		}
		r.pos += 4
		vt, err := r.u32()
		if err != nil || vt != 60 {
			continue
		}
		vc, err := r.i32()
		if err != nil {
			break
		}
		fc, err := r.i32()
		if err != nil {
			break
		}
		if vc <= 0 || vc > 50_000_000 || fc != vc*3 {
			continue
		}
		verts := make([][3]float64, 0, vc)
		ok := true
		for i := int32(0); i < vc; i++ {
			x, err1 := r.f32()
			y, err2 := r.f32()
			z, err3 := r.f32()
			if err1 != nil || err2 != nil || err3 != nil {
				ok = false
				break
			}
			verts = append(verts, [3]float64{float64(x), float64(y), float64(z)})
		}
		if !ok {
			break
		}
		blocks = append(blocks, VertexBlock{ElementType: elemType, VertexCount: int(vc), Vertices: verts})
	}
	return blocks, nil
}

// File.DecodeGeometryVertices convenience is defined in nwd.go.
var _ = fmt.Sprintf
