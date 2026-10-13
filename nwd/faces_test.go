package nwd

import (
	"encoding/binary"
	"testing"
)

func TestReadBits(t *testing.T) {
	// one word 0xB8000000 = 1011 1000 ...; row0 = 101b = 5, row1 = 110b = 6.
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], 0xB8000000)
	vals, pos, err := ReadBits(data[:], 0, []byte{3, 0, 0, 0}, 2, 2)
	if err != nil {
		t.Fatalf("ReadBits: %v", err)
	}
	if len(vals) != 2 || vals[0] != 5 || vals[1] != 6 {
		t.Errorf("vals=%v want [5 6]", vals)
	}
	if pos != 4 {
		t.Errorf("pos=%d want 4", pos)
	}
}

func TestReadVertexesPerLineUncompressed(t *testing.T) {
	// [u32 n=2][u16 3][u16 4]
	data := []byte{2, 0, 0, 0, 3, 0, 4, 0}
	v, _, err := ReadVertexesPerLine(data, 0, false, true, 0)
	if err != nil {
		t.Fatalf("ReadVertexesPerLine: %v", err)
	}
	if len(v) != 2 || v[0] != 3 || v[1] != 4 {
		t.Errorf("vpl=%v want [3 4]", v)
	}
}

func TestReadIndexesPerLineUncompressed(t *testing.T) {
	// [i32 n=3][u16 10][u16 11][u16 12]
	data := []byte{3, 0, 0, 0, 10, 0, 11, 0, 12, 0}
	idx, _, err := ReadIndexesPerLine(data, 0, false, true, 0)
	if err != nil {
		t.Fatalf("ReadIndexesPerLine: %v", err)
	}
	if len(idx) != 3 || idx[0] != 10 || idx[1] != 11 || idx[2] != 12 {
		t.Errorf("ipl=%v want [10 11 12]", idx)
	}
}

func TestReadVertexesPerLineCompressed(t *testing.T) {
	// [u32 total=3][i32 bits=2][i32 unique=2][word 0xE0000000=11 10..]
	// then index table bytes {0x01 (run of 2: 0,1), 0x42 (backref 2 -> 0)}
	// => tbl=[0,1,0] -> vals[tbl]=[3,2,3]
	buf := make([]byte, 0, 32)
	buf = appendFaceU32(buf, 3)          // total
	buf = appendFaceU32(buf, 2)          // bits
	buf = appendFaceU32(buf, 2)          // unique
	buf = appendFaceU32(buf, 0xE0000000) // bit word
	buf = append(buf, 0x01, 0x42)        // index table
	v, _, err := ReadVertexesPerLine(buf, 0, true, true, 0)
	if err != nil {
		t.Fatalf("ReadVertexesPerLine: %v", err)
	}
	want := []uint16{3, 2, 3}
	if len(v) != len(want) {
		t.Fatalf("vpl=%v want %v", v, want)
	}
	for i := range want {
		if v[i] != want[i] {
			t.Errorf("vpl[%d]=%d want %d", i, v[i], want[i])
		}
	}
}

func TestSplitFaces(t *testing.T) {
	faces := SplitFaces([]uint16{0, 1, 2, 3, 4, 5}, []uint16{3, 3})
	if len(faces) != 2 {
		t.Fatalf("faces=%d want 2", len(faces))
	}
	if faces[0][0] != 0 || faces[1][2] != 5 {
		t.Errorf("faces=%v", faces)
	}
}

func appendFaceU32(b []byte, v uint32) []byte {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	return append(b, t[:]...)
}
