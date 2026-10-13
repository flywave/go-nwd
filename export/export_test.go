package export

import (
	"path/filepath"
	"testing"

	"github.com/flywave/gltf"
	mst "github.com/flywave/go-mst"

	"github.com/flywave/go-nwd/nwd"
)

func sample() *nwd.SceneMesh {
	return &nwd.SceneMesh{
		Vertices:  [][3]float64{{0, 0, 0}, {1, 0, 0}, {0, 1, 0}, {0, 0, 1}},
		Triangles: [][3]uint32{{0, 1, 2}, {0, 1, 3}},
		Lines:     [][2]uint32{{2, 3}},
	}
}

func TestWriteMST(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.mst")
	if err := WriteMST(p, sample(), [3]byte{200, 200, 200}); err != nil {
		t.Fatalf("WriteMST: %v", err)
	}
	m, err := mst.MeshReadFrom(p)
	if err != nil {
		t.Fatalf("MeshReadFrom: %v", err)
	}
	if len(m.Instances) != 1 {
		t.Fatalf("instances=%d want 1", len(m.Instances))
	}
	var faces int
	for _, g := range m.Instances[0].Mesh.Nodes[0].FaceGroup {
		faces += len(g.Faces)
	}
	if faces != 2 {
		t.Errorf("faces=%d want 2", faces)
	}
	var edges int
	for _, g := range m.Instances[0].Mesh.Nodes[0].EdgeGroup {
		edges += len(g.Edges)
	}
	if edges != 1 {
		t.Errorf("edges=%d want 1", edges)
	}
}

func TestWriteGLTF(t *testing.T) {
	for _, binary := range []bool{true, false} {
		ext := ".glb"
		if !binary {
			ext = ".gltf"
		}
		p := filepath.Join(t.TempDir(), "a"+ext)
		if err := WriteGLTF(p, sample(), binary, [3]float32{0.5, 0.5, 0.5}); err != nil {
			t.Fatalf("WriteGLTF(binary=%v): %v", binary, err)
		}
		doc, err := gltf.Open(p)
		if err != nil {
			t.Fatalf("gltf.Open(binary=%v): %v", binary, err)
		}
		if len(doc.Meshes) != 1 || len(doc.Meshes[0].Primitives) != 2 {
			t.Errorf("binary=%v meshes=%d prims=%d", binary, len(doc.Meshes), len(doc.Meshes[0].Primitives))
		}
	}
}
