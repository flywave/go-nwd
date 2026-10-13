package nwd

import (
	"encoding/binary"
	"math"
)

// Text element decoding (findings N115).
//
// OdNwGraphicTextElementReader::readElement@0xc316f4 reads, in order:
//
//	readString<align0> text          // i32 byte length + UTF-8 + pad to 4
//	f32 xScale, f32 yScale, f32 rotateAngle
//	f32*3 rotateAxis
//	f32*3 leftPoint
//	f32*3 rightPoint
//	i32 fontId
//
// Text geometry carries no triangles (it needs a font to tessellate), so it is
// surfaced as metadata only.

// TextGeometry is a decoded text (type 103) element.
type TextGeometry struct {
	Text        string
	XScale      float32
	YScale      float32
	RotateAngle float32
	RotateAxis  [3]float64
	Left        [3]float64
	Right       [3]float64
	FontID      int
}

// decodeTextElement decodes a text element payload starting at p (after the
// 8-byte element envelope). It returns the text and the position after the
// payload.
func decodeTextElement(data []byte, p int) (*TextGeometry, int, bool) {
	t := &TextGeometry{}
	if p+4 > len(data) {
		return nil, p, false
	}
	n := int(int32(binary.LittleEndian.Uint32(data[p:])))
	p += 4
	if n > 0 {
		if p+n > len(data) {
			return nil, p, false
		}
		t.Text = string(data[p : p+n])
		p = AlignUp(p+n, 4)
	}
	floats := 3 + 3 + 3 + 3 // scales/angle + axis + left + right
	if p+floats*4+4 > len(data) {
		return nil, p, false
	}
	rf := func() float32 {
		v := math.Float32frombits(binary.LittleEndian.Uint32(data[p:]))
		p += 4
		return v
	}
	t.XScale = rf()
	t.YScale = rf()
	t.RotateAngle = rf()
	for i := 0; i < 3; i++ {
		t.RotateAxis[i] = float64(rf())
	}
	for i := 0; i < 3; i++ {
		t.Left[i] = float64(rf())
	}
	for i := 0; i < 3; i++ {
		t.Right[i] = float64(rf())
	}
	t.FontID = int(int32(binary.LittleEndian.Uint32(data[p:])))
	p += 4
	return t, p, true
}
