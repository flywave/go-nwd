package nwd

import "testing"

// TestLogicalHierarchyBCCCH walks the real BCCCH LogicalHierarchy stream
// (findings N117/N118). Assertions pin the stream-level grammar (blocks,
// root marker, child count), the first top-level items and the tolerance
// behaviour on the not-yet-decoded exotic node variants.
func TestLogicalHierarchyBCCCH(t *testing.T) {
	f := openReal(t)
	li := f.StreamByName("LcOpNwdLogicalHierarchy")
	if li < 0 {
		t.Skip("no LogicalHierarchy stream")
	}
	ld, err := f.StreamData(li)
	if err != nil {
		t.Fatal(err)
	}
	if len(ld) < 8 {
		t.Fatalf("logical hierarchy too small: %d", len(ld))
	}
	h, err := DecodeLogicalHierarchy(ld, true)
	if err != nil {
		t.Fatal(err)
	}
	// Stream-level grammar.
	if len(h.Blocks) != 10 {
		t.Errorf("props blocks = %d, want 10", len(h.Blocks))
	}
	var sum uint32
	for _, b := range h.Blocks {
		sum += b
	}
	if sum != 97271 {
		t.Errorf("props blocks sum = %d, want 97271", sum)
	}
	if len(h.Children) < 1 {
		t.Fatalf("no top-level children decoded")
	}
	root := h.Children[0]
	if root.TypeID != PartitionNode || root.UserName != "BCCCH_SITE_LAND.nwc" {
		t.Errorf("top[0] = %s(%d) %q, want PartitionNode BCCCH_SITE_LAND.nwc",
			root.TypeName, root.TypeID, root.UserName)
	}
	if root.GuidIndex != 5401 {
		t.Errorf("root guidIndex = %d, want 5401", root.GuidIndex)
	}
	// Tolerance: the walk reports its gaps instead of failing.
	if len(h.Gaps) == 0 {
		t.Errorf("expected reported gaps on exotic node variants")
	}
	t.Logf("children=%d objects=%d maxDepth=%d gaps=%d tail=%d",
		len(h.Children), h.Objects, h.MaxDepth, len(h.Gaps), h.TailFlag)
}

// TestLogicalHierarchyGateHouse pins the grammar on the v431 sample.
func TestLogicalHierarchyGateHouse(t *testing.T) {
	f := openRealGateHouse(t)
	li := f.StreamByName("gatehouse.nwd\\LcOpNwdLogicalHierarchy")
	if li < 0 {
		t.Skip("no LogicalHierarchy stream")
	}
	ld, err := f.StreamData(li)
	if err != nil {
		t.Fatal(err)
	}
	// GateHouse may not carry PartitionProps: try both header forms.
	h, err := DecodeLogicalHierarchy(ld, false)
	if err != nil {
		h, err = DecodeLogicalHierarchy(ld, true)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Children) < 1 {
		t.Fatalf("no children decoded")
	}
	t.Logf("children=%d blocks=%d gaps=%d", len(h.Children), len(h.Blocks), len(h.Gaps))
}

// TestGuidStoreBCCCH pins the GUID store grammar and the guidIndex
// linkage (findings N118).
func TestGuidStoreBCCCH(t *testing.T) {
	f := openReal(t)
	gi := f.StreamByName("LcOpGuidStore")
	if gi < 0 {
		t.Skip("no GuidStore stream")
	}
	gd, err := f.StreamData(gi)
	if err != nil {
		t.Fatal(err)
	}
	guids, err := DecodeGuidStore(gd)
	if err != nil {
		t.Fatal(err)
	}
	if len(guids) != 9466 {
		t.Errorf("guids = %d, want 9466", len(guids))
	}
	if got, want := guids[0], "ef760b00-7108-46ac-bca4-c6737c4ec081"; got != want {
		t.Errorf("guid[0] = %s, want %s", got, want)
	}
}

// TestPropertyAttributeReadData decodes the first PropertyAttribute of
// the BCCCH LogicalHierarchy and pins its typed field values (findings
// N118: [attrFlags][count][key object + NwDataType + value]×count).
func TestPropertyAttributeReadData(t *testing.T) {
	f := openReal(t)
	li := f.StreamByName("LcOpNwdLogicalHierarchy")
	ld, err := f.StreamData(li)
	if err != nil {
		t.Fatal(err)
	}
	or := &ObjectReader{r: &byteReader{buf: ld, pos: 624}, FormatVersion: formatVersionGate}
	obj, err := or.ReadObject()
	if err != nil {
		t.Fatalf("property attribute: %v", err)
	}
	if obj.TypeID != 86 || obj.Attribute == nil {
		t.Fatalf("type = %s, want PropertyAttribute with payload", obj.TypeName)
	}
	props := obj.Attribute.Props
	if len(props) != 17 {
		t.Fatalf("fields = %d, want 17", len(props))
	}
	want := map[int]struct{ key, str string }{
		0:  {"Name", "BASE NAVD"},
		1:  {"Type", "6.35mm(1/4in) Head (Existing)"},
		8:  {"COBie.CreatedBy", "Frederic.Herbere@stantec.com"},
		10: {"COBie.Floor.Elevation", "0"},
		16: {"Workset", "Shared Levels and Grids"},
	}
	for i, w := range want {
		if props[i].Key != w.key || props[i].Str != w.str {
			t.Errorf("field[%d] = (%q,%q), want (%q,%q)", i, props[i].Key, props[i].Str, w.key, w.str)
		}
	}
	if props[15].FieldType != 3 || props[15].Number != 1 {
		t.Errorf("field[15] (Structural) = type %d num %d, want BOOL true",
			props[15].FieldType, props[15].Number)
	}
	if or.r.pos != 2060 {
		t.Errorf("end pos = %d, want 2060", or.r.pos)
	}
}
