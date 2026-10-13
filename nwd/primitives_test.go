package nwd

import (
	"encoding/binary"
	"math"
	"testing"
)

func putF32(b []byte, o int, v float32) { binary.LittleEndian.PutUint32(b[o:], math.Float32bits(v)) }

// layout: [i32 flags][f32x3 origin][f32x3 xVector][f32x3 yVector][f32 radius]
func TestTessellateCircle(t *testing.T) {
	b := make([]byte, 44)
	putF32(b, 4, 1)  // origin.x = 1
	putF32(b, 16, 1) // xVector = (1,0,0)
	putF32(b, 32, 1) // yVector = (0,1,0)
	putF32(b, 40, 2) // radius = 2
	verts, tris, ok := decodeCircleElement(b, 0)
	if !ok {
		t.Fatal("decodeCircleElement failed")
	}
	if len(verts) != primSegments || len(tris) != primSegments-2 {
		t.Fatalf("ring=%d tris=%d", len(verts), len(tris))
	}
	// all ring points at distance 2 from origin (1,0,0), in the z=0 plane
	for _, v := range verts {
		d := math.Sqrt((v[0]-1)*(v[0]-1) + v[1]*v[1] + v[2]*v[2])
		if math.Abs(d-2) > 1e-4 || math.Abs(v[2]) > 1e-6 {
			t.Errorf("point %v distance %.4f want 2", v, d)
		}
	}
}

// layout: [i32 flags][bottom][top][xAxis][yAxis][radius]
func TestTessellateCylinder(t *testing.T) {
	b := make([]byte, 56)
	// bottom (0,0,0); top (0,0,3)
	putF32(b, 24, 3) // top.z = 3
	putF32(b, 28, 1) // xAxis = (1,0,0)
	putF32(b, 44, 1) // yAxis = (0,1,0)
	putF32(b, 52, 1) // radius = 1
	verts, tris, ok := decodeCylinderElement(b, 0)
	if !ok {
		t.Fatal("decodeCylinderElement failed")
	}
	if len(verts) != 2*primSegments {
		t.Fatalf("verts=%d want %d", len(verts), 2*primSegments)
	}
	want := 2*primSegments + 2*(primSegments-2)
	if len(tris) != want {
		t.Fatalf("tris=%d want %d", len(tris), want)
	}
	// ring points at distance 1 from the axis (x=y=0), z in {0,3}
	for i, v := range verts {
		if math.Abs(math.Hypot(v[0], v[1])-1) > 1e-4 {
			t.Errorf("vert %d %v not radius 1", i, v)
		}
	}
}

// End-to-end: a synthetic stream with a Circle element flows into DecodeMesh.
func TestDecodeMeshPrimitive(t *testing.T) {
	b := make([]byte, 8+44)
	binary.LittleEndian.PutUint32(b[0:], uint32(envNewBase)) // marker 100
	binary.LittleEndian.PutUint32(b[4:], 104)                // CircleElement
	putF32(b, 8+16, 1)                                       // xVector
	putF32(b, 8+28, 1)                                       // yVector
	putF32(b, 8+40, 2)                                       // radius
	m := DecodeMesh(b, 0)
	if len(m.Triangles) != primSegments-2 {
		t.Fatalf("triangles=%d want %d", len(m.Triangles), primSegments-2)
	}
}
