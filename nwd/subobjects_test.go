package nwd

import (
	"math"
	"testing"
)

// TestDecodeNormalShort pins the NormalSetShort(100) value reconstruction
// (findings N88/N92): an F-bit signed component is scaled to 16 bits and the
// vector is normalized.
func TestDecodeNormalShort(t *testing.T) {
	// n=1, unique=1, F=8; one bit word whose three 8-bit components are all 0x40
	// (= +64 signed). 64 << (16-8) = 0x4000, normalized to (1,1,1)/sqrt(3).
	buf := appendFaceU32(nil, 1)         // n
	buf = appendFaceU32(buf, 1)          // unique
	buf = appendFaceU32(buf, 0x40404000) // bit word (bits read MSB-first)
	v := decodeNormalShort(buf, 0, 8)
	if len(v) != 1 {
		t.Fatalf("normals=%v want 1", v)
	}
	want := 1 / math.Sqrt(3)
	for c := 0; c < 3; c++ {
		if math.Abs(v[0][c]-want) > 1e-9 {
			t.Errorf("normal[%d]=%v want %v", c, v[0][c], want)
		}
	}

	// unique==0: no bit-pack, every normal is empty (zero vector) and the
	// n-entry index table carries the run.
	buf = appendFaceU32(nil, 3) // n
	buf = appendFaceU32(buf, 0) // unique
	buf = append(buf, 0x00)     // index table: run of 1 -> [0]
	buf = append(buf, 0x82)     // repeat last 3 -> [0,0,0]
	v = decodeNormalShort(buf, 0, 8)
	if len(v) != 3 {
		t.Fatalf("unique0 normals=%v want 3", v)
	}
	for i, n := range v {
		if n != [3]float64{} {
			t.Errorf("normal[%d]=%v want zero", i, n)
		}
	}
}
