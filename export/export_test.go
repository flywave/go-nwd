package export

import (
	"path/filepath"
	"testing"

	"github.com/flywave/gltf"
	"github.com/flywave/gltf/modeler"
	mst "github.com/flywave/go-mst"
	"github.com/flywave/go3d/vec3"

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

// TestWriteGLTFUsesMeshNormals verifies the export prefers the mesh's own
// per-vertex normals (findings N92/N93) over computed smooth normals.
func TestWriteGLTFUsesMeshNormals(t *testing.T) {
	m := sample()
	m.Normals = [][3]float64{{0, 0, -1}, {0, -1, 0}, {-1, 0, 0}, {0, 0, -1}}
	p := filepath.Join(t.TempDir(), "n.gltf")
	if err := WriteGLTF(p, m, false, [3]float32{0.5, 0.5, 0.5}); err != nil {
		t.Fatalf("WriteGLTF: %v", err)
	}
	doc, err := gltf.Open(p)
	if err != nil {
		t.Fatalf("gltf.Open: %v", err)
	}
	idx := doc.Meshes[0].Primitives[0].Attributes[gltf.NORMAL]
	got, err := modeler.ReadNormal(doc, doc.Accessors[idx], nil)
	if err != nil {
		t.Fatalf("ReadNormal: %v", err)
	}
	want := [][3]float32{{0, 0, -1}, {0, -1, 0}, {-1, 0, 0}, {0, 0, -1}}
	if len(got) != len(want) {
		t.Fatalf("normals=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("normal[%d]=%v want %v", i, got[i], want[i])
		}
	}
}

// TestWriteMSTUsesMeshNormals verifies the MST export writes the mesh's own
// per-vertex normals when present (findings N94).
func TestWriteMSTUsesMeshNormals(t *testing.T) {
	m := sample()
	m.Normals = [][3]float64{{0, 0, -1}, {0, -1, 0}, {-1, 0, 0}, {0, 0, -1}}
	p := filepath.Join(t.TempDir(), "n.mst")
	if err := WriteMST(p, m, [3]byte{200, 200, 200}); err != nil {
		t.Fatalf("WriteMST: %v", err)
	}
	got, err := mst.MeshReadFrom(p)
	if err != nil {
		t.Fatalf("MeshReadFrom: %v", err)
	}
	nd := got.Instances[0].Mesh.Nodes[0]
	if len(nd.Normals) != 4 {
		t.Fatalf("normals=%d want 4", len(nd.Normals))
	}
	if nd.Normals[1] != (vec3.T{0, -1, 0}) {
		t.Errorf("normal[1]=%v want (0,-1,0)", nd.Normals[1])
	}
}
