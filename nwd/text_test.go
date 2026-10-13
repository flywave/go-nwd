package nwd

import (
	"encoding/binary"
	"math"
	"testing"
)

func f32b(b []byte, v float32) []byte {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], math.Float32bits(v))
	return append(b, t[:]...)
}

// TestDecodeTextElement pins the Text(103) payload grammar (finding N115):
// string, xScale/yScale/rotateAngle, rotateAxis, leftPoint, rightPoint, fontId.
func TestDecodeTextElement(t *testing.T) {
	var b []byte
	b = appendFaceU32(b, 100) // element marker
	b = appendFaceU32(b, 103) // typeID Text
	// string "Hi": len 2 + bytes + pad to 4
	b = appendFaceU32(b, 2)
	b = append(b, 'H', 'i', 0, 0)
	b = f32b(b, 1.5) // xScale
	b = f32b(b, 2.5) // yScale
	b = f32b(b, 0.25)
	b = f32b(b, 0) // axis
	b = f32b(b, 1)
	b = f32b(b, 0)
	b = f32b(b, 1) // left
	b = f32b(b, 2)
	b = f32b(b, 3)
	b = f32b(b, 4) // right
	b = f32b(b, 5)
	b = f32b(b, 6)
	b = appendFaceU32(b, 7) // fontId

	txt, _, ok := decodeTextElement(b, 8)
	if !ok {
		t.Fatal("decodeTextElement failed")
	}
	if txt.Text != "Hi" || txt.XScale != 1.5 || txt.YScale != 2.5 || txt.RotateAngle != 0.25 {
		t.Errorf("text=%q scales=%v/%v rot=%v", txt.Text, txt.XScale, txt.YScale, txt.RotateAngle)
	}
	if txt.RotateAxis != [3]float64{0, 1, 0} || txt.Left != [3]float64{1, 2, 3} || txt.Right != [3]float64{4, 5, 6} {
		t.Errorf("axis=%v left=%v right=%v", txt.RotateAxis, txt.Left, txt.Right)
	}
	if txt.FontID != 7 {
		t.Errorf("fontId=%d want 7", txt.FontID)
	}

	// End-to-end: the decoder surfaces text elements.
	els := DecodeElements(b, 0)
	if len(els) != 1 || els[0].ElementType != 103 || els[0].Text == nil || els[0].Text.Text != "Hi" {
		t.Errorf("DecodeElements text = %+v", els)
	}
}
