package nwstream

import (
	"bytes"
	"errors"
	"testing"
)

func TestDetectHeaderVariants(t *testing.T) {
	cases := []struct {
		name     string
		hdr      []byte
		wantOK   bool
		wantMode Mode
		wantVer  int
	}{
		{
			name: "ascii-lichunk-v8", hdr: pad52(SigASCIILichunk, '8'),
			wantOK: true, wantMode: ModeASCIILichunk, wantVer: 8,
		},
		{
			name: "binary-lichunk-v8", hdr: pad52(SigBinaryLichunk, '8'),
			wantOK: true, wantMode: ModeBinaryLichunk, wantVer: 8,
		},
		{
			name: "binary-navisworks-v8", hdr: pad52(SigBinaryNavisworksPrefix, '8'),
			wantOK: true, wantMode: ModeBinaryNavisworks, wantVer: 8,
		},
		{
			name: "ascii-lichunk-v7", hdr: pad52(SigASCIILichunk, '7'),
			wantOK: true, wantMode: ModeASCIILichunk, wantVer: 7,
		},
		{
			name: "not nwd", hdr: pad52("PK\x03\x04-not-a-signature-at-all-here!!", '0'),
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, ok := DetectHeader(tc.hdr)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if cfg.Mode != tc.wantMode {
				t.Errorf("mode=%v want %v", cfg.Mode, tc.wantMode)
			}
			if cfg.Version != tc.wantVer {
				t.Errorf("version=%d want %d", cfg.Version, tc.wantVer)
			}
		})
	}
}

func TestParseEmptyTOC(t *testing.T) {
	img := BuildSyntheticV8(nil, nil)
	c, err := Parse(img)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Config.Version != 8 {
		t.Errorf("version=%d want 8", c.Config.Version)
	}
	if len(c.Streams) != 0 {
		t.Errorf("streams=%d want 0", len(c.Streams))
	}
	if c.FileSize != int64(len(img)) {
		t.Errorf("FileSize=%d want %d", c.FileSize, len(img))
	}
}

func TestParseUncompressedStream(t *testing.T) {
	payload := []byte("HELLO-UNCOMPRESSED-STREAM")
	img := BuildSyntheticV8([]SynthStream{{
		Name:   "LcOpNwdPartition",
		Middle: payload,
	}}, nil)
	c, err := Parse(img)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Streams) != 1 {
		t.Fatalf("streams=%d want 1", len(c.Streams))
	}
	s := c.Streams[0]
	if s.Name != "LcOpNwdPartition" {
		t.Errorf("name=%q", s.Name)
	}
	if s.Compressed() {
		t.Error("unexpected compressed flag")
	}
	if s.Size != int64(len(payload)) {
		t.Errorf("size=%d want %d", s.Size, len(payload))
	}
	data, err := c.StreamData(0)
	if err != nil {
		t.Fatalf("StreamData: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("data=%q want %q", data, payload)
	}
}

func TestParseCompressedStream(t *testing.T) {
	payload := bytes.Repeat([]byte("compressed-nwd-payload-"), 40)
	img := BuildSyntheticV8([]SynthStream{{
		Name:       "LcOpNwdGeometryCompress",
		Middle:     payload,
		Compressed: true,
	}}, nil)
	c, err := Parse(img)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !c.Streams[0].Compressed() {
		t.Fatal("expected compressed flag")
	}
	if c.Streams[0].Size <= 0 {
		t.Errorf("size=%d", c.Streams[0].Size)
	}
	data, err := c.StreamData(0)
	if err != nil {
		t.Fatalf("StreamData: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("round-trip mismatch (got %d bytes)", len(data))
	}
}

func TestParsePrefixSuffix(t *testing.T) {
	prefix := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	middle := []byte("middle-content")
	suffix := []byte{0xBE, 0xEF}
	img := BuildSyntheticV8([]SynthStream{{
		Name:   "LcOpNwdFragments",
		Prefix: prefix,
		Middle: middle,
		Suffix: suffix,
	}}, nil)
	c, err := Parse(img)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s := c.Streams[0]
	if s.Prefix != 4 || s.Suffix != 2 {
		t.Errorf("prefix/suffix=%d/%d want 4/2", s.Prefix, s.Suffix)
	}
	if s.Size != int64(len(prefix)+len(middle)+len(suffix)) {
		t.Errorf("size=%d", s.Size)
	}
	gotPrefix, err := c.StreamPrefix(0)
	if err != nil {
		t.Fatalf("StreamPrefix: %v", err)
	}
	if !bytes.Equal(gotPrefix, prefix) {
		t.Errorf("prefix=%x", gotPrefix)
	}
	data, err := c.StreamData(0)
	if err != nil {
		t.Fatalf("StreamData: %v", err)
	}
	if !bytes.Equal(data, middle) {
		t.Errorf("middle=%q want %q", data, middle)
	}
}

func TestParseMultiStream(t *testing.T) {
	img := BuildSyntheticV8([]SynthStream{
		{Name: "LcOpNwdPartition", Middle: []byte("part-a")},
		{Name: "LcOpNwdSpatialHierarchy", Middle: []byte("spatial-b-payload"), Compressed: true},
		{Name: "LcOpNwdGeometryCompress", Middle: []byte("geom-c"), Prefix: []byte{1, 2}},
	}, []byte{0xAA, 0xBB}) // gap filler
	c, err := Parse(img)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Streams) != 3 {
		t.Fatalf("streams=%d want 3", len(c.Streams))
	}
	for i, want := range []string{"LcOpNwdPartition", "LcOpNwdSpatialHierarchy", "LcOpNwdGeometryCompress"} {
		if c.Streams[i].Name != want {
			t.Errorf("stream[%d]=%q want %q", i, c.Streams[i].Name, want)
		}
	}
	d1, _ := c.StreamData(1)
	if string(d1) != "spatial-b-payload" {
		t.Errorf("stream1 data=%q", d1)
	}
	d2, _ := c.StreamData(2)
	if string(d2) != "geom-c" {
		t.Errorf("stream2 data=%q", d2)
	}
}

func TestParseErrors(t *testing.T) {
	img := BuildSyntheticV8([]SynthStream{{Name: "LcOpNwdPartition", Middle: []byte("x")}}, nil)

	t.Run("footer mismatch", func(t *testing.T) {
		bad := append([]byte(nil), img...)
		bad[len(bad)-1] ^= 0xff
		if _, err := Parse(bad); !errors.Is(err, ErrFooterMismatch) {
			t.Fatalf("err=%v want ErrFooterMismatch", err)
		}
	})

	t.Run("v7 unsupported", func(t *testing.T) {
		bad := append([]byte(nil), img...)
		bad[SigCmpLen] = '7'
		copy(bad[len(bad)-HeaderSize:], bad[:HeaderSize])
		if _, err := Parse(bad); !errors.Is(err, ErrUnsupportedVersion) {
			t.Fatalf("err=%v want ErrUnsupportedVersion", err)
		}
	})

	t.Run("not nwd", func(t *testing.T) {
		if _, err := Parse(make([]byte, 256)); !errors.Is(err, ErrNotNWD) {
			t.Fatalf("err=%v want ErrNotNWD", err)
		}
	})

	t.Run("too small", func(t *testing.T) {
		if _, err := Parse([]byte("short")); err == nil {
			t.Fatal("want error for tiny input")
		}
	})
}

func pad52(sig string, ver byte) []byte {
	b := make([]byte, HeaderSize)
	copy(b, sig)
	if len(sig) < HeaderSize {
		b[len(sig)] = ver
	}
	return b
}
