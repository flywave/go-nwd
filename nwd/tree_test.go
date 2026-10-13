package nwd

import (
	"errors"
	"testing"
)

func TestPartitionNodeRoundTrip(t *testing.T) {
	w := NewObjectWriter()
	w.PartitionNode("My Project", "Level 1", "Site", 1, 0x3, 7)
	w.End()

	tree, err := DecodeTree(w.Bytes())
	if err != nil {
		t.Fatalf("DecodeTree: %v", err)
	}
	root := tree.Root
	if root.TypeID != PartitionNode {
		t.Fatalf("root type=%d", root.TypeID)
	}
	if root.UserName != "My Project" {
		t.Errorf("user_name=%q", root.UserName)
	}
	if root.ClassName != "Site" || root.DisplayName != "Level 1" {
		t.Errorf("class=%q display=%q", root.ClassName, root.DisplayName)
	}
	if root.ModelType == nil || *root.ModelType != 1 {
		t.Errorf("model_type=%v", root.ModelType)
	}
	if root.Flags != 0x3 || root.GuidIndex != 7 {
		t.Errorf("flags/guid=%#x/%d", root.Flags, root.GuidIndex)
	}
	if tree.Objects != 1 {
		t.Errorf("top-level objects=%d want 1", tree.Objects)
	}
}

func TestGroupNodeChildren(t *testing.T) {
	w := NewObjectWriter()
	// Group node with two children (GroupModelItemNode, type 53).
	w.GroupNode("Level A", "Floor", "Slab", 0x10, 1, 2, func(ow *ObjectWriter) {
		ow.GroupNode("Room 101", "Space", "Office", 0, 2, 0, nil)
		ow.GroupNode("Room 102", "Space", "Lab", 0, 3, 0, nil)
	})
	w.End()

	or := NewObjectReader(w.Bytes(), formatVersionGate)
	root, err := or.ReadObject()
	if err != nil {
		t.Fatalf("ReadObject: %v", err)
	}
	if root.TypeID != GroupModelItemNode {
		t.Fatalf("type=%d", root.TypeID)
	}
	if root.UserName != "Level A" {
		t.Errorf("user=%q", root.UserName)
	}
	if len(root.Children) != 2 {
		t.Fatalf("children=%d want 2", len(root.Children))
	}
	if root.Children[0].UserName != "Room 101" || root.Children[1].UserName != "Room 102" {
		t.Errorf("children=%q,%q", root.Children[0].UserName, root.Children[1].UserName)
	}
	if root.Children[0].TypeName != "OdNwGroupModelItemNode" {
		t.Errorf("child type=%q", root.Children[0].TypeName)
	}
}

func TestBackref(t *testing.T) {
	w := NewObjectWriter()
	w.Name("A", "B")
	w.WriteBackref(0)
	w.End()

	or := NewObjectReader(w.Bytes(), formatVersionGate)
	first, err := or.ReadObject()
	if err != nil || first == nil || first.TypeID != TypeName {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	ref, err := or.ReadObject()
	if err != nil {
		t.Fatalf("backref: %v", err)
	}
	if ref.TypeID != -1 || ref.Index != 0 {
		t.Errorf("ref=%+v", ref)
	}
}

func TestCensusUnsupportedType(t *testing.T) {
	w := NewObjectWriter()
	w.PartitionNode("P", "C", "W", 0, 0, 0)
	w.BeginNew(106) // Plot type — no payload decoder
	c := CensusStream(w.Bytes(), formatVersionGate)
	if c.Err == nil || !errors.Is(c.Err, ErrUnsupportedType) {
		t.Fatalf("census err=%v want ErrUnsupportedType", c.Err)
	}
	if c.ByType[PartitionNode] != 1 {
		t.Errorf("by_type=%v", c.ByType)
	}
}

func TestObjTypeTable(t *testing.T) {
	if ObjTypeName(TypePartitionNode) != "OdNwPartitionNode" {
		t.Errorf("32=%q", ObjTypeName(TypePartitionNode))
	}
	if ObjTypeName(106) != "OdNwPlotGeometryAttribute" {
		t.Errorf("106=%q", ObjTypeName(106))
	}
	if len(objTypeNames) != 110 {
		t.Errorf("registry size=%d want 110", len(objTypeNames))
	}
	if ObjTypeName(999) != "" {
		t.Errorf("unknown id should be empty")
	}
}

func TestFormatVersionLayout(t *testing.T) {
	// The ModelItem layout is shared across the versions we implement; the
	// reader accepts any FormatVersion (older-version divergences are U10).
	w := NewObjectWriter()
	w.PartitionNode("P", "C", "W", 0, 0, 0)
	w.End()
	for _, v := range []uint32{22, 248, 451} {
		or := NewObjectReader(w.Bytes(), v)
		o, err := or.ReadObject()
		if err != nil {
			t.Fatalf("version %d: %v", v, err)
		}
		if o == nil || o.UserName != "P" {
			t.Errorf("version %d: %+v", v, o)
		}
	}
}
