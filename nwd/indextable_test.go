package nwd

import "testing"

func TestDecodeIndexTableSynthetic(t *testing.T) {
	// Verified against readIndexTable@0xc275de.
	//  0x02 -> run of 3            : 0,1,2
	//  0x81 -> repeat last twice   : 2,2
	//  0x42 -> backref 2 positions : out[3] = 2
	//  0xD5 -> literal ~5          : 0xFFFFFFFA
	//  0xF0 01 02 -> lit16         : 0x0102
	data := []byte{0x02, 0x81, 0x42, 0xD5, 0xF0, 0x01, 0x02}
	idx, end, err := DecodeIndexTable(data, 0, 8)
	if err != nil {
		t.Fatalf("DecodeIndexTable: %v", err)
	}
	want := []uint32{0, 1, 2, 2, 2, 2, 0xFFFFFFFA, 0x0102}
	if len(idx) != len(want) {
		t.Fatalf("len=%d want %d (%v)", len(idx), len(want), idx)
	}
	for i := range want {
		if idx[i] != want[i] {
			t.Errorf("idx[%d]=%d want %d", i, idx[i], want[i])
		}
	}
	if end != len(data) {
		t.Errorf("consumed=%d want %d", end, len(data))
	}
}

func TestDecodeIndexTableBackref12AndLit32(t *testing.T) {
	//  0xE0 01 -> backref12 offset 1  : copy last again
	//  0xF1 DE AD BE EF -> lit32       : 0xDEADBEEF
	data := []byte{0x02, 0xE0, 0x01, 0xF1, 0xDE, 0xAD, 0xBE, 0xEF}
	idx, _, err := DecodeIndexTable(data, 0, 5)
	if err != nil {
		t.Fatalf("DecodeIndexTable: %v", err)
	}
	want := []uint32{0, 1, 2, 2, 0xDEADBEEF}
	if len(idx) != len(want) {
		t.Fatalf("len=%d want %d (%v)", len(idx), len(want), idx)
	}
	for i := range want {
		if idx[i] != want[i] {
			t.Errorf("idx[%d]=%d want %d", i, idx[i], want[i])
		}
	}
}

// TestDecodeIndexTableReal exercises the codec end-to-end on the real 431
// sample, whose geometry uses the shared-position-pool + index-table path.
func TestDecodeIndexTableReal(t *testing.T) {
	f := openRealGateHouse(t)
	gi := f.StreamByName("gatehouse.nwd\\LcOpNwdGeometry")
	if gi < 0 {
		t.Fatal("geometry stream not found")
	}
	blocks, err := f.DecodeGeometryVertices(gi, 0)
	if err != nil {
		t.Fatalf("DecodeGeometryVertices: %v", err)
	}
	indexed := 0
	for _, b := range blocks {
		if b.IndexCount > 0 {
			indexed++
		}
	}
	if indexed == 0 {
		t.Fatal("expected at least one index-table block in the 431 sample")
	}
}
