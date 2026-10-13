package nwd

import (
	"encoding/binary"
	"math"
)

// Fragment stream decoding (findings N95).
//
// The Fragments stream (LcOpNwdFragments) is a flat object stream: a leading
// u32 record count, then one object envelope per fragment
// (marker >= 100, typeID 13 = OdNwFragment). Each fragment body starts with an
// 8-byte alignment, then (OdNwFragmentReader::readElement@0xc5cac6):
//
//	[align8] f64 traversableScale
//	         u32 traversableTris
//	         u32 flags
//	         u32 fragmentFlags
//	         [align8] readObject(transform 14-17 or geometry ref 93)
//	         ... RunPath and version-gated trailing fields
//
// A fragment links a model item to geometry (a transform + a geometry object)
// and is what makes instancing possible; the per-record tail is version-gated
// and not yet fully walked.

// FragmentHeader is the fixed prefix of a fragment record.
type FragmentHeader struct {
	Scale         float64
	Tris          uint32
	Flags         uint32
	FragmentFlags uint32
}

// StreamFragments is the internal stream name of the fragments stream.
const StreamFragments = "LcOpNwdFragments"

// FragmentRecord is one decoded fragment (findings N95/N99/N103): its header
// fields, its placement transform (type 14-17) and the index of the geometry it
// references (type 93 GeometryRef). GeomIndex is -1 when no ref follows; it is
// 1-based into the geometry stream's elements (findings N106), so the referenced
// element is GeomElementIndex().
type FragmentRecord struct {
	Scale         float64
	Tris          uint32
	Flags         uint32
	FragmentFlags uint32
	Transform     *Transform
	GeomIndex     int
	RefMin        [3]float32 // geometry ref local bbox (findings N103)
	RefMax        [3]float32
}

// GeomElementIndex returns the 0-based index into the geometry stream's element
// list for this fragment's geometry ref, or -1 when absent (findings N106:
// GeomIndex is 1-based).
func (r FragmentRecord) GeomElementIndex() int {
	if r.GeomIndex <= 0 {
		return -1
	}
	return r.GeomIndex - 1
}

// DecodeFragments walks every fragment record in the stream. Record lengths are
// version-gated and not fully walked, so a single resynchronising pass locates
// OdNwFragment(13) envelopes (validated by a plausible traversable scale) and
// attributes the following transform(14-17) and geometry ref(93) child
// envelopes to the current record (findings N99/N101/N103).
func DecodeFragments(data []byte) []FragmentRecord {
	var out []FragmentRecord
	n := len(data)
	cur := -1
	for pos := 4; pos+24 <= n; pos += 4 {
		if binary.LittleEndian.Uint32(data[pos:]) < uint32(envNewBase) {
			continue
		}
		switch tt := int(binary.LittleEndian.Uint32(data[pos+4:])); tt {
		case 13:
			rec, ok := parseFragmentHeader(data, pos)
			if !ok {
				cur = -1
				continue
			}
			out = append(out, rec)
			cur = len(out) - 1
		case 93:
			if cur >= 0 && out[cur].GeomIndex < 0 {
				if gi, mn, mx, ok := geometryRefIndex(data, pos); ok {
					out[cur].GeomIndex = gi
					out[cur].RefMin, out[cur].RefMax = mn, mx
				}
			}
		}
	}
	return out
}

// parseFragmentHeader reads a fragment header at envelope pos.
func parseFragmentHeader(data []byte, pos int) (FragmentRecord, bool) {
	n := len(data)
	p := AlignUp(pos+12, 8)
	if p+20 > n {
		return FragmentRecord{}, false
	}
	scale := math.Float64frombits(binary.LittleEndian.Uint64(data[p:]))
	if scale <= 0 || scale > 1000 {
		return FragmentRecord{}, false
	}
	rec := FragmentRecord{
		Scale:         scale,
		Tris:          binary.LittleEndian.Uint32(data[p+8:]),
		Flags:         binary.LittleEndian.Uint32(data[p+12:]),
		FragmentFlags: binary.LittleEndian.Uint32(data[p+16:]),
		GeomIndex:     -1,
	}
	// The placement transform (type 14-17) follows at align8(p+20) when present.
	q := AlignUp(p+20, 8)
	if q+8 <= n && binary.LittleEndian.Uint32(data[q:]) >= uint32(envNewBase) {
		if tt := int(binary.LittleEndian.Uint32(data[q+4:])); tt >= 14 && tt <= 17 {
			if t, _, ok := decodeTransformAt(data, q+8, tt); ok {
				rec.Transform = t
			}
		}
	}
	return rec, true
}

// geometryRefIndex decodes the geometry index of an OdNwGraphicGeometryRef(93)
// payload at envelope pos (findings N103): bbox(2*f32*3) then align8, userOffset
// (3*f64), userScale(f32), a checksum when formatVersion>4, then the u32
// geometry index.
func geometryRefIndex(data []byte, pos int) (int, [3]float32, [3]float32, bool) {
	n := len(data)
	if pos+8+24 > n {
		return 0, [3]float32{}, [3]float32{}, false
	}
	var mn, mx [3]float32
	for c := 0; c < 3; c++ {
		mn[c] = math.Float32frombits(binary.LittleEndian.Uint32(data[pos+8+c*4:]))
		mx[c] = math.Float32frombits(binary.LittleEndian.Uint32(data[pos+20+c*4:]))
	}
	q := AlignUp(pos+8+24, 8) + 24 + 4 + 4
	if q+4 > n {
		return 0, mn, mx, false
	}
	gi := int(binary.LittleEndian.Uint32(data[q:]))
	if gi < 0 || gi >= 1_000_000 {
		return 0, mn, mx, false
	}
	return gi, mn, mx, true
}

// decodeTransformAt decodes a placement object payload (findings N32) at p,
// after the 8-byte object alignment, for transform type IDs 14-17.
func decodeTransformAt(data []byte, p, typeID int) (*Transform, int, bool) {
	p = AlignUp(p, 8)
	t := &Transform{Kind: transformKindByType[typeID]}
	switch typeID {
	case 14: // translation: 3 doubles
		if p+24 > len(data) {
			return nil, p, false
		}
		t.Translation = f64x3(data, p)
		return t, p + 24, true
	case 15, 16: // translation + quaternion (+ scale)
		need := 56
		if typeID == 16 {
			need = 64
		}
		if p+need > len(data) {
			return nil, p, false
		}
		t.Translation = f64x3(data, p)
		for i := 0; i < 4; i++ {
			t.Rotation[i] = math.Float64frombits(binary.LittleEndian.Uint64(data[p+24+i*8:]))
		}
		if typeID == 16 {
			t.Scale = math.Float64frombits(binary.LittleEndian.Uint64(data[p+56:]))
		}
		return t, p + need, true
	case 17: // 4x4 f32 matrix (row-major)
		if p+64 > len(data) {
			return nil, p, false
		}
		for i := 0; i < 16; i++ {
			t.Matrix[i] = float64(math.Float32frombits(binary.LittleEndian.Uint32(data[p+i*4:])))
		}
		t.HasMatrix = true
		return t, p + 64, true
	}
	return nil, p, false
}

func f64x3(data []byte, p int) [3]float64 {
	return [3]float64{
		math.Float64frombits(binary.LittleEndian.Uint64(data[p:])),
		math.Float64frombits(binary.LittleEndian.Uint64(data[p+8:])),
		math.Float64frombits(binary.LittleEndian.Uint64(data[p+16:])),
	}
}

// DecodeFragmentsHeader reads the fragments-stream count and the first record's
// fixed header fields. It returns ok=false when the stream does not open with a
// fragment count followed by an OdNwFragment(13) envelope.
func DecodeFragmentsHeader(data []byte) (count int, first FragmentHeader, ok bool) {
	if len(data) < 40 {
		return 0, FragmentHeader{}, false
	}
	count = int(int32(binary.LittleEndian.Uint32(data)))
	if count <= 0 || count > 100_000_000 {
		return 0, FragmentHeader{}, false
	}
	if binary.LittleEndian.Uint32(data[4:]) < uint32(envNewBase) || binary.LittleEndian.Uint32(data[8:]) != 13 {
		return 0, FragmentHeader{}, false
	}
	p := AlignUp(12, 8)
	if p+16 > len(data) {
		return 0, FragmentHeader{}, false
	}
	first.Scale = math.Float64frombits(binary.LittleEndian.Uint64(data[p:]))
	first.Tris = binary.LittleEndian.Uint32(data[p+8:])
	first.Flags = binary.LittleEndian.Uint32(data[p+12:])
	if p+20 <= len(data) {
		first.FragmentFlags = binary.LittleEndian.Uint32(data[p+16:])
	}
	return count, first, true
}
