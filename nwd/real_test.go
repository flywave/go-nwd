package nwd

import (
	"os"
	"path/filepath"
	"testing"
)

// Real NWD golden test. The 25 MB sample lives in nwd/testdata; the test is
// skipped when it is absent so the suite still runs without the sample.
const realSample = "testdata/BCCCH_BIM Coordination Model_251024.nwd"

func openReal(t *testing.T) *File {
	t.Helper()
	if _, err := os.Stat(filepath.Join(".", realSample)); err != nil {
		t.Skipf("real sample not present: %v", err)
	}
	buf, err := os.ReadFile(realSample)
	if err != nil {
		t.Fatal(err)
	}
	f, err := Open(buf)
	if err != nil {
		t.Fatalf("Open real sample: %v", err)
	}
	return f
}

func TestRealContainerInventory(t *testing.T) {
	f := openReal(t)
	md := f.Metadata

	if md.Kind != KindBinaryLichunk {
		t.Errorf("kind=%v want nwd-binary-lichunk", md.Kind)
	}
	if md.Version != 8 {
		t.Errorf("container version=%d want 8", md.Version)
	}
	if md.FileSize != 25675348 {
		t.Errorf("file size=%d want 25675348", md.FileSize)
	}
	if len(md.Streams) != 27 {
		t.Fatalf("streams=%d want 27", len(md.Streams))
	}

	// Spot-check streams decoded from the real trailing TOC.
	want := map[string][2]int64{ // name -> {offset, size}
		"cache\\LcOpNwdGeometryCompress": {52, 40},
		"cache\\LcOpNwdGeometry":         {92, 21670465},
		"cache\\LcOpNwdPartition":        {21670568, 346},
		"LcOpCommonSchemas":              {25674483, 11},
		"LcOpXRefTable":                  {25674494, 133},
	}
	byName := map[string]StreamInfo{}
	for _, s := range md.Streams {
		byName[s.Name] = s
	}
	for name, osz := range want {
		s, ok := byName[name]
		if !ok {
			t.Errorf("stream %q missing", name)
			continue
		}
		if s.Offset != osz[0] || s.Size != osz[1] {
			t.Errorf("stream %q offset/size=%d/%d want %d/%d", name, s.Offset, s.Size, osz[0], osz[1])
		}
	}

	// All streams except the encrypted GeometryCompress container are zlib.
	compressed := 0
	for _, s := range md.Streams {
		if s.Compressed {
			compressed++
		}
	}
	if compressed != 26 {
		t.Errorf("compressed streams=%d want 26", compressed)
	}
	if g := byName["cache\\LcOpNwdGeometryCompress"]; g.Compressed {
		t.Error("GeometryCompress should not be zlib")
	}
}

func TestRealStreamInflate(t *testing.T) {
	f := openReal(t)

	// Every zlib stream must inflate without error.
	for i, s := range f.Metadata.Streams {
		if !s.Compressed {
			continue
		}
		data, err := f.StreamData(i)
		if err != nil {
			t.Errorf("stream %q (%d) inflate: %v", s.Name, i, err)
			if len(s.Name) > 0 {
				continue
			}
		}
		_ = data
	}

	// The Partition stream inflates to a PartitionNode object envelope.
	pi := f.StreamByName("LcOpNwdPartition")
	if pi < 0 {
		t.Fatal("partition stream not found")
	}
	data, err := f.StreamData(pi)
	if err != nil {
		t.Fatalf("partition inflate: %v", err)
	}
	// marker=100 (new object 0), typeID=32 (PartitionNode).
	if len(data) < 8 || data[0] != 100 || data[4] != 32 {
		t.Errorf("partition head=% x, want 64 00 00 00 20 00 00 00", data[:min(8, len(data))])
	}
}

func TestRealPartitionRoot(t *testing.T) {
	f := openReal(t)
	pi := f.StreamByName("LcOpNwdPartition")
	if pi < 0 {
		t.Fatal("partition stream not found")
	}
	root, err := f.DecodePartitionRoot(pi)
	if err != nil {
		t.Fatalf("DecodePartitionRoot: %v", err)
	}
	if root.UserName != "BCCCH_BIM Coordination Model_251024.nwd" {
		t.Errorf("user_name=%q", root.UserName)
	}
	if root.ClassName != "LcOaPartition" {
		t.Errorf("class_name=%q", root.ClassName)
	}
	if root.DisplayName != "File" {
		t.Errorf("display_name=%q", root.DisplayName)
	}
	if root.AttrCount != 1 || root.FirstAttrType != 92 {
		t.Errorf("attr_count=%d first_attr=%d want 1/92", root.AttrCount, root.FirstAttrType)
	}
}

func TestRealPropertyNames(t *testing.T) {
	f := openReal(t)
	pi := f.StreamByName("LcOaPartitionProps")
	if pi < 0 {
		t.Fatal("PartitionProps stream not found")
	}
	names, err := f.ScanStreamNames(pi, 4000)
	if err != nil {
		t.Fatalf("ScanStreamNames: %v", err)
	}
	if len(names) < 100 {
		t.Fatalf("extracted %d names, want >=100", len(names))
	}
	found := map[string]bool{}
	for _, n := range names {
		found[n.Name] = true
	}
	for _, want := range []string{
		"revit_Latitude", "revit_Longitude", "revit_Elevation",
		"LcRevitPropertyLocation", "LcOaSceneIdentity",
		"lcldrevit_parameter_Center Radius",
	} {
		if !found[want] {
			t.Errorf("missing property name %q", want)
		}
	}
}

func TestRealGeometryVertices(t *testing.T) {
	f := openReal(t)
	gi := f.StreamByName("LcOpNwdGeometry")
	if gi < 0 {
		t.Fatal("Geometry stream not found")
	}
	blocks, err := f.DecodeGeometryVertices(gi, 20000)
	if err != nil {
		t.Fatalf("DecodeGeometryVertices: %v", err)
	}
	if len(blocks) < 1000 {
		t.Fatalf("blocks=%d want >=1000", len(blocks))
	}
	total := 0
	for _, b := range blocks {
		total += b.VertexCount
	}
	if total < 100000 {
		t.Errorf("total vertices=%d want >=100000", total)
	}
	// First block is a triangle element with 687 vertices.
	b0 := blocks[0]
	if b0.ElementType != 94 || b0.VertexCount != 687 {
		t.Errorf("block0 elem/vc=%d/%d want 94/687", b0.ElementType, b0.VertexCount)
	}
	if len(b0.Vertices) != 687 {
		t.Errorf("block0 vertices=%d", len(b0.Vertices))
	}
}

func TestRealPartitionObjects(t *testing.T) {
	f := openReal(t)
	pi := f.StreamByName("LcOpNwdPartition")
	if pi < 0 {
		t.Fatal("partition stream not found")
	}
	os, err := f.DecodeObjectStream(pi, 451, 0)
	if err != nil {
		t.Fatalf("DecodeObjectStream: %v", err)
	}
	if len(os.Objects) == 0 {
		t.Fatal("no objects decoded")
	}
	root := os.Objects[0]
	if root.TypeID != PartitionNode || root.UserName != "BCCCH_BIM Coordination Model_251024.nwd" {
		t.Fatalf("root=%+v", root)
	}
	if root.ClassName != "LcOaPartition" {
		t.Errorf("class=%q", root.ClassName)
	}
	if len(root.Attrs) != 1 {
		t.Fatalf("root attrs=%d want 1", len(root.Attrs))
	}
	pub := root.Attrs[0]
	if pub.Kind != AttrPublish || pub.TypeID != 92 {
		t.Errorf("attr=%+v", pub)
	}
	// Real publish timestamp (2025-10-31).
	if pub.PublishDate < 1_700_000_000 || pub.PublishDate > 1_800_000_000 {
		t.Errorf("publish_date=%d out of plausible range", pub.PublishDate)
	}
}
