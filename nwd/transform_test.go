package nwd

import (
	"testing"
)

func TestTransformRoundTrip(t *testing.T) {
	w := NewObjectWriter()
	w.BeginNew(14) // ObjTranslation
	w.WriteTransformPayload(&Transform{Kind: TransformTranslation, Translation: [3]float64{1, 2, 3}})
	w.BeginNew(15) // ObjTransRot
	w.WriteTransformPayload(&Transform{
		Kind: TransformTransRot, Translation: [3]float64{4, 5, 6}, Rotation: [4]float64{0, 0, 0, 1},
	})
	w.BeginNew(16) // ObjTransRotScale
	w.WriteTransformPayload(&Transform{
		Kind: TransformTransRotScale, Translation: [3]float64{7, 8, 9},
		Rotation: [4]float64{0, 0, 0, 1}, Scale: 2.5,
	})
	w.End()

	or := NewObjectReader(w.Bytes(), formatVersionGate)
	o1, err := or.ReadObject()
	if err != nil {
		t.Fatalf("obj1: %v", err)
	}
	if o1.Transform == nil || o1.Transform.Translation != [3]float64{1, 2, 3} {
		t.Errorf("obj1=%+v", o1.Transform)
	}
	o2, err := or.ReadObject()
	if err != nil {
		t.Fatalf("obj2: %v", err)
	}
	if o2.Transform.Rotation != [4]float64{0, 0, 0, 1} {
		t.Errorf("obj2 rotation=%v", o2.Transform.Rotation)
	}
	o3, err := or.ReadObject()
	if err != nil {
		t.Fatalf("obj3: %v", err)
	}
	if o3.Transform.Scale != 2.5 || o3.Transform.Translation != [3]float64{7, 8, 9} {
		t.Errorf("obj3=%+v", o3.Transform)
	}
}

func TestTransformMatrix4(t *testing.T) {
	tr := &Transform{Kind: TransformTranslation, Translation: [3]float64{10, 20, 30}}
	m := tr.Matrix4()
	// identity rotation, translation in row 3.
	if m[0] != 1 || m[5] != 1 || m[10] != 1 || m[15] != 1 {
		t.Errorf("rotation part=%v", m)
	}
	if m[12] != 10 || m[13] != 20 || m[14] != 30 {
		t.Errorf("translation part=%v", m[12:16])
	}
}

func TestSceneAssembly(t *testing.T) {
	w := NewObjectWriter()
	w.PartitionNode("Root", "Building", "IfcBuilding", 0, 0, 0)
	w.GroupNode("Floor 1", "Storey", "IfcBuildingStorey", 0, 1, 0, nil)
	w.End()

	tree, err := DecodeTree(w.Bytes())
	if err != nil {
		t.Fatalf("DecodeTree: %v", err)
	}
	mesh := &Mesh{Vertices: [][3]float64{{0, 0, 0}, {1, 0, 0}, {0, 1, 0}}, Triangles: []uint32{0, 1, 2}}
	scene := BuildScene(tree, mesh)
	if scene.Nodes != 1 {
		t.Errorf("nodes=%d want 1", scene.Nodes)
	}
	if scene.WithMesh != 1 {
		t.Errorf("with_mesh=%d want 1", scene.WithMesh)
	}
	if len(scene.Instances) != 1 {
		t.Fatalf("instances=%d", len(scene.Instances))
	}
	if scene.Instances[0].Name != "Root" {
		t.Errorf("name=%q", scene.Instances[0].Name)
	}
}
