package nwd

import (
	"encoding/binary"
	"math"
)

// ElementGeometry is one geometry element (TriangleSet/LineSet/PointSet) with
// its decoded vertex set and, when locatable, its face arrays.
type ElementGeometry struct {
	Start, End  int
	ElementType int // 94 triangle, 95 line, 96 point
	Vertices    [][3]float64
	Normals     [][3]float64 // per-vertex normals when a NormalSet child is present
	PerFace     []uint16     // vertices per face (from vertexesPerLine)
	Indices     []uint16     // flat index list (from indexesPerLine)
	FacesFound  bool
	Text        *TextGeometry // set for text elements (type 103)
}

// DecodeElements walks the geometry stream, extracts every element envelope and
// its VertexSet, then attempts to locate the vertexesPerLine/indexesPerLine
// arrays (findings N74/N75/N77). Face arrays are accepted only when
// sum(perFace) == len(indices), which validated exactly on the real sample.
func DecodeElements(stream []byte, limit int) []ElementGeometry {
	n := len(stream)
	var starts []int
	for pos := 0; pos+8 <= n; pos++ {
		if binary.LittleEndian.Uint32(stream[pos:]) != uint32(envNewBase) {
			continue
		}
		t := int(binary.LittleEndian.Uint32(stream[pos+4:]))
		if t == 94 || t == 95 || t == 96 || t == 103 || t == 104 || t == 105 {
			starts = append(starts, pos)
		}
	}
	var out []ElementGeometry
	for i, s := range starts {
		e := n
		if i+1 < len(starts) {
			e = starts[i+1]
		}
		typ := int(binary.LittleEndian.Uint32(stream[s+4:]))
		// Text elements carry metadata only (tessellation needs a font).
		if typ == 103 {
			el := ElementGeometry{Start: s, End: e, ElementType: typ}
			if txt, _, ok := decodeTextElement(stream, s+8); ok {
				el.Text = txt
			}
			out = append(out, el)
			continue
		}
		// Analytic primitives carry no VertexSet child.
		switch typ {
		case 104:
			if verts, tris, ok := decodeCircleElement(stream, s+8); ok {
				out = append(out, primitiveElement(s, e, typ, verts, tris))
			} else {
				out = append(out, ElementGeometry{Start: s, End: e, ElementType: typ})
			}
			continue
		case 105:
			if verts, tris, ok := decodeCylinderElement(stream, s+8); ok {
				out = append(out, primitiveElement(s, e, typ, verts, tris))
			} else {
				out = append(out, ElementGeometry{Start: s, End: e, ElementType: typ})
			}
			continue
		}
		el := ElementGeometry{Start: s, End: e, ElementType: typ}
		vs := s + 8
		if vs+16 <= n && binary.LittleEndian.Uint32(stream[vs:]) == uint32(envNewBase+1) &&
			binary.LittleEndian.Uint32(stream[vs+4:]) == 60 {
			verts, vsEnd, ok := decodeVertexSet(stream, vs)
			if ok {
				el.Vertices = verts
				// Deterministic child-object traversal first (N87); fall back to
				// the boundary-anchored scan for layouts the walker does not
				// recognise (N80). Both produce identical faces on the 451 sample.
				if perFace, idx, normals, ok := locateFacesDeterministic(stream, vsEnd, e); ok {
					el.PerFace, el.Indices, el.Normals, el.FacesFound = perFace, idx, normals, true
				} else if perFace, idx, ok := locateFaceArrays(stream, vsEnd, e); ok {
					el.PerFace, el.Indices, el.FacesFound = perFace, idx, true
				}
			}
		}
		out = append(out, el)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// decodeVertexSet decodes a VertexSet body (marker already validated).
func decodeVertexSet(stream []byte, vs int) ([][3]float64, int, bool) {
	n := len(stream)
	if vs+16 > n {
		return nil, vs, false
	}
	vc := int32(binary.LittleEndian.Uint32(stream[vs+8:]))
	fc := int32(binary.LittleEndian.Uint32(stream[vs+12:]))
	if vc <= 0 || vc > 50_000_000 || fc < 3 || fc%3 != 0 {
		return nil, vs, false
	}
	start := vs + 16
	end := start + int(fc)*4
	if end > n {
		return nil, vs, false
	}
	pool := make([][3]float64, 0, fc/3)
	for i := 0; i < int(fc)/3; i++ {
		o := start + i*12
		pool = append(pool, [3]float64{
			float64(math.Float32frombits(binary.LittleEndian.Uint32(stream[o:]))),
			float64(math.Float32frombits(binary.LittleEndian.Uint32(stream[o+4:]))),
			float64(math.Float32frombits(binary.LittleEndian.Uint32(stream[o+8:]))),
		})
	}
	if fc/3 == vc {
		return pool, end, true
	}
	idx, np, err := DecodeIndexTable(stream, end, int(vc))
	if err != nil {
		return nil, vs, false
	}
	verts := make([][3]float64, 0, len(idx))
	for _, k := range idx {
		if int(k) >= len(pool) {
			return nil, vs, false
		}
		verts = append(verts, pool[k])
	}
	return verts, np, len(verts) > 0
}

// locateFaceArrays searches [lo,hi) for a self-consistent
// vertexesPerLine + indexesPerLine pair whose index list terminates at the
// element boundary hi (findings N77). This tight end-match rejects the vast
// majority of coincidental matches.
func locateFaceArrays(stream []byte, lo, hi int) ([]uint16, []uint16, bool) {
	for o := lo; o+12 <= hi; o += 4 {
		perFace, ip, ok := tryVPL(stream, o, hi)
		if !ok {
			continue
		}
		idx, end, ok := tryIPL(stream, ip, hi)
		if !ok {
			continue
		}
		if end < hi-16 || end > hi {
			continue
		}
		sum := 0
		for _, c := range perFace {
			sum += int(c)
		}
		if sum == len(idx) && len(perFace) > 0 {
			return perFace, idx, true
		}
	}
	return nil, nil, false
}

// tryVPL attempts to read vertexesPerLine at o (compressed or uncompressed).
func tryVPL(stream []byte, o, hi int) ([]uint16, int, bool) {
	n := len(stream)
	if o+4 > n {
		return nil, o, false
	}
	total := int(int32(binary.LittleEndian.Uint32(stream[o:])))
	// uncompressed candidate: [u32 n][n*u16] all in a plausible range.
	if total > 0 && total <= 200000 && o+4+total*2 <= n {
		all := true
		for k := 0; k < total; k++ {
			v := int16(binary.LittleEndian.Uint16(stream[o+4+2*k:]))
			if v == 0 || v < -256 || v > 256 {
				all = false
				break
			}
		}
		if all {
			per := make([]uint16, total)
			for k := 0; k < total; k++ {
				per[k] = binary.LittleEndian.Uint16(stream[o+4+2*k:])
			}
			return per, AlignUp(o+4+total*2, 4), true
		}
	}
	// compressed candidate: [u32 total][align8][i32 bits][i32 unique][words]
	if total <= 0 || total > 200000 {
		return nil, o, false
	}
	p := AlignUp(o+4, 4)
	if p+8 > n {
		return nil, o, false
	}
	bits := int(int32(binary.LittleEndian.Uint32(stream[p:])))
	unique := int(int32(binary.LittleEndian.Uint32(stream[p+4:])))
	if bits < 1 || bits > 32 || unique < 1 || unique > total {
		return nil, o, false
	}
	vals, np, err := ReadBits(stream, p+8, []byte{byte(bits), 0, 0, 0}, unique, unique)
	if err != nil {
		return nil, o, false
	}
	per := make([]uint16, 0, total)
	if unique < total {
		tbl, np2, err := DecodeIndexTable(stream, np, total)
		if err != nil {
			return nil, o, false
		}
		np = np2
		for _, k := range tbl {
			if int(k) >= len(vals) {
				return nil, o, false
			}
			per = append(per, uint16(vals[k]))
		}
	} else {
		for i := 0; i < total; i++ {
			per = append(per, uint16(vals[i]))
		}
	}
	return per, np, true
}

// tryIPL attempts to read indexesPerLine at o (compressed or uncompressed).
func tryIPL(stream []byte, o, hi int) ([]uint16, int, bool) {
	n := len(stream)
	p := AlignUp(o, 4)
	if p+4 > n {
		return nil, o, false
	}
	count := int(int32(binary.LittleEndian.Uint32(stream[p:])))
	if count <= 0 || count > 2_000_000 {
		return nil, o, false
	}
	// compressed: [i32 n][index table]
	if tbl, np, err := DecodeIndexTable(stream, p+4, count); err == nil && np <= hi+64 {
		idx := make([]uint16, len(tbl))
		for i, v := range tbl {
			idx[i] = uint16(v)
		}
		return idx, np, true
	}
	return nil, o, false
}
