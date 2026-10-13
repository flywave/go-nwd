package nwd

import (
	"bytes"
	"testing"
)

func TestVertexSetRoundTrip(t *testing.T) {
	verts := [][3]float64{
		{0, 0, 0}, {1, 0, 0}, {1, 1, 0}, {0, 1, 0},
		{0, 0, 1}, {1, 0, 1}, {1, 1, 1}, {0, 1, 1},
	}
	enc := EncodeVertexSet(verts)
	got, err := DecodeVertexSet(enc)
	if err != nil {
		t.Fatalf("DecodeVertexSet: %v", err)
	}
	if len(got) != len(verts) {
		t.Fatalf("count=%d want %d", len(got), len(verts))
	}
	for i := range verts {
		for j := 0; j < 3; j++ {
			if got[i][j] != verts[i][j] {
				t.Errorf("v[%d][%d]=%v want %v", i, j, got[i][j], verts[i][j])
			}
		}
	}
}

func TestMeshBuild(t *testing.T) {
	verts := [][3]float64{{0, 0, 0}, {1, 0, 0}, {0, 1, 0}}
	tris := []uint32{0, 1, 2}
	m, err := BuildMesh(EncodeVertexSet(verts), EncodeIndexList(tris))
	if err != nil {
		t.Fatalf("BuildMesh: %v", err)
	}
	if len(m.Vertices) != 3 || len(m.Triangles) != 3 {
		t.Errorf("mesh=%+v", m)
	}

	// out-of-range index
	if _, err := BuildMesh(EncodeVertexSet(verts), EncodeIndexList([]uint32{0, 1, 9})); err == nil {
		t.Error("want error for out-of-range index")
	}
	// non-multiple-of-3
	if _, err := BuildMesh(EncodeVertexSet(verts), EncodeIndexList([]uint32{0, 1})); err == nil {
		t.Error("want error for index count not multiple of 3")
	}
}

func TestGeometryBlockRoundTrip(t *testing.T) {
	b1 := EncodeVertexSet([][3]float64{{0, 0, 0}, {2, 3, 4}})
	b2 := EncodeIndexList([]uint32{0, 1, 0})
	enc, err := BuildGeometryBlocks([][]byte{b1, b2})
	if err != nil {
		t.Fatalf("BuildGeometryBlocks: %v", err)
	}
	if len(enc)%8 != 0 {
		t.Fatalf("encrypted length %d not multiple of 8", len(enc))
	}

	blocks, err := DecodeGeometryBlocks(enc)
	if err != nil {
		t.Fatalf("DecodeGeometryBlocks: %v", err)
	}
	if len(blocks) != 2 {
		t.Fatalf("blocks=%d want 2", len(blocks))
	}
	if !bytes.Equal(blocks[0].Data, b1) || !bytes.Equal(blocks[1].Data, b2) {
		t.Errorf("block data mismatch")
	}
	// Decode the vertex set out of block 0.
	vs, err := DecodeVertexSet(blocks[0].Data)
	if err != nil {
		t.Fatalf("DecodeVertexSet: %v", err)
	}
	if len(vs) != 2 || vs[1][2] != 4 {
		t.Errorf("verts=%v", vs)
	}
}

func TestDecryptGeometryStreamBadLength(t *testing.T) {
	if _, err := DecryptGeometryStream(make([]byte, 7)); err == nil {
		t.Error("want error for non-multiple-of-8 length")
	}
}
