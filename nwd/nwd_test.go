package nwd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/flywave/go-nwd/internal/nwstream"
)

func TestDetectAndParse(t *testing.T) {
	img := nwstream.BuildSyntheticV8([]nwstream.SynthStream{
		{Name: "LcOpNwdSpatialHierarchy", Middle: []byte("spatial-data"), Compressed: true},
		{Name: "LcOpNwdGeometryCompress", Middle: []byte("geom-data")},
	}, nil)

	if got := Detect(img); got != KindASCIILichunk {
		t.Fatalf("Detect=%v want KindASCIILichunk", got)
	}
	if got := Detect([]byte("not nwd at all................................")); got != KindUnknown {
		t.Fatalf("Detect(non-nwd)=%v want KindUnknown", got)
	}

	f, err := Open(img)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	md := f.Metadata
	if md.Kind != KindASCIILichunk || md.Version != 8 {
		t.Errorf("kind/version=%v/%d", md.Kind, md.Version)
	}
	if len(md.Streams) != 2 {
		t.Fatalf("streams=%d want 2", len(md.Streams))
	}
	if md.Streams[0].Name != "LcOpNwdSpatialHierarchy" || !md.Streams[0].Compressed {
		t.Errorf("stream0=%+v", md.Streams[0])
	}
	if md.Streams[1].Name != "LcOpNwdGeometryCompress" || md.Streams[1].Compressed {
		t.Errorf("stream1=%+v", md.Streams[1])
	}

	// StreamByName + StreamData.
	idx := f.StreamByName("LcOpNwdSpatialHierarchy")
	if idx != 0 {
		t.Fatalf("StreamByName=%d", idx)
	}
	data, err := f.StreamData(idx)
	if err != nil {
		t.Fatalf("StreamData: %v", err)
	}
	if string(data) != "spatial-data" {
		t.Errorf("data=%q", data)
	}

	if _, err := json.Marshal(md); err != nil {
		t.Fatalf("json: %v", err)
	}
}

func TestOpenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic.nwd")
	payload := []byte("file-payload-bytes")
	img := nwstream.BuildSyntheticV8([]nwstream.SynthStream{
		{Name: "LcOpNwdPartition", Middle: payload},
	}, nil)
	if err := os.WriteFile(path, img, 0o644); err != nil {
		t.Fatal(err)
	}
	md, err := OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if md.FileSize != int64(len(img)) {
		t.Errorf("FileSize=%d want %d", md.FileSize, len(img))
	}
	if md.Streams[0].Size != int64(len(payload)) {
		t.Errorf("stream size=%d want %d", md.Streams[0].Size, len(payload))
	}
	// MainPayload covers stream regions (no gap filler used here).
	if md.MainPayloadSize < len(payload) {
		t.Errorf("MainPayloadSize=%d", md.MainPayloadSize)
	}
}

func TestEndToEndTreeFromFile(t *testing.T) {
	tw := NewObjectWriter()
	tw.PartitionNode("Project", "Building", "IfcBuilding", 1, 1, 1, 1, 0, func(ow *ObjectWriter) {
		ow.GroupNode("Floor 1", "IfcBuildingStorey", "Storey", 0, 2, 0, nil)
	})
	tw.End()

	img := nwstream.BuildSyntheticV8([]nwstream.SynthStream{
		{Name: "LcOpNwdPartition", Middle: tw.Bytes()},
	}, nil)

	dir := t.TempDir()
	path := dir + "/tree.nwd"
	if err := os.WriteFile(path, img, 0o644); err != nil {
		t.Fatal(err)
	}
	md, err := OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	_ = md

	f, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := f.DecodeTree(f.StreamByName("LcOpNwdPartition"))
	if err != nil {
		t.Fatalf("DecodeTree: %v", err)
	}
	if tree.Root.UserName != "Project" || len(tree.Root.Children) != 1 {
		t.Fatalf("tree=%+v", tree.Root)
	}
	if tree.Root.Children[0].UserName != "Floor 1" {
		t.Errorf("child=%q", tree.Root.Children[0].UserName)
	}
}
