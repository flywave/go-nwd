package nwd

import (
	"encoding/binary"
	"math"
)

// Deterministic element child-object walking (findings N74/N87).
//
// OdNwGraphicTriangleSetElementReader::readElement@0xc2c1ea reads exactly four
// child objects positionally via OdNwObjectReaderManager::readObject (expected
// types 60 VertexSet / 61 TexCoordSet / 0 NormalSet / 58 ColorSet); a missing
// child is written as an envelope whose marker is 0 (envNil). After the four
// children it reads vertexesPerLine, aligns to 4, then reads indexesPerLine.
//
// Child payload grammars (from the readers):
//
//	VertexSet(60)      [i32 vc][i32 fc][fc*f32]  (+ index table when fc<3*vc)  N71
//	TexCoordSet(61)    [i32 n][n*(f32,f32)]                                    @0xc29ad0
//	NormalSetFloat(59) [i32 n][n*(f32,f32,f32)]                                @0xc22926
//	ColorSet(58)       [i32 a][i32 n][n*u32]                                 rest @0xc201b4
//	NormalSetShort(100)                                                         @0xc222e4
//	     [i32 n][i32 unique][readBits(flags=[F,F,F,0], unique, 3*unique)]
//	     then, when unique < n, an index table of n entries.
//
// F (precision-reduced flags) comes from unreadable geometry-compress settings
// (see U20); it defaults to 16 when the stored value is 0 or >15. Because it is
// not recoverable, the walker enumerates the small candidate set and accepts
// only the parse that lands exactly on the element boundary.

// envelopeKind classifies the object envelope marker.
type envelopeKind int

const (
	envKInvalid envelopeKind = iota
	envKNil
	envKBackref
	envKNew
)

// readEnvelope inspects the object envelope at pos.
func readEnvelope(data []byte, pos int) (kind envelopeKind, typeID int, next int) {
	if pos+4 > len(data) {
		return envKInvalid, 0, pos
	}
	m := binary.LittleEndian.Uint32(data[pos:])
	switch {
	case m == uint32(envNil):
		return envKNil, 0, pos + 4
	case m == uint32(envBackref):
		return envKBackref, 0, pos + 8
	case m >= uint32(envNewBase):
		if pos+8 > len(data) {
			return envKInvalid, 0, pos
		}
		return envKNew, int(binary.LittleEndian.Uint32(data[pos+4:])), pos + 8
	}
	return envKInvalid, 0, pos
}

// skipTexCoord skips a TexCoordSet(61) body: [i32 n][n*(f32,f32)].
func skipTexCoord(data []byte, p int) (int, bool) {
	if p+4 > len(data) {
		return p, false
	}
	n := int(int32(binary.LittleEndian.Uint32(data[p:])))
	if n < 0 || n > 5_000_000 {
		return p, false
	}
	end := p + 4 + n*8
	if end > len(data) {
		return p, false
	}
	return end, true
}

// skipNormalFloat skips a NormalSetFloat(59) body: [i32 n][n*(f32,f32,f32)].
func skipNormalFloat(data []byte, p int) (int, bool) {
	if p+4 > len(data) {
		return p, false
	}
	n := int(int32(binary.LittleEndian.Uint32(data[p:])))
	if n < 0 || n > 5_000_000 {
		return p, false
	}
	end := p + 4 + n*12
	if end > len(data) {
		return p, false
	}
	return end, true
}

// skipColor skips a ColorSet(58) body, uncompressed form [i32 a][i32 n][n*u32]
// aligned to 4.
func skipColor(data []byte, p int) (int, bool) {
	if p+8 > len(data) {
		return p, false
	}
	n := int(int32(binary.LittleEndian.Uint32(data[p+4:])))
	if n < 0 || n > 5_000_000 {
		return p, false
	}
	end := p + 8 + n*4
	if end > len(data) {
		return p, false
	}
	return AlignUp(end, 4), true
}

// readBitsEnd returns the stream position after a readBits bit-pack of
// sum(flags)*count bits at pos.
func readBitsEnd(data []byte, pos int, flags []byte, count int) (int, bool) {
	sum := 0
	for _, f := range flags {
		sum += int(f)
	}
	words := (sum*count + 31) / 32
	end := pos + words*4
	if sum < 0 || count < 0 || end > len(data) {
		return pos, false
	}
	return end, true
}

// nsCand is one candidate parse of a NormalSetShort(100) body: its consumed end
// and the precision flag F that produced it.
type nsCand struct {
	end int
	f   int
}

// normalShortCandidates returns every plausible parse of a NormalSetShort(100)
// body at p, one per candidate precision flag F (see finding N88). F comes from
// the unreadable geometry-compress settings; the end-anchored element walk
// disambiguates it.
func normalShortCandidates(data []byte, p int) []nsCand {
	if p+8 > len(data) {
		return nil
	}
	n := int(int32(binary.LittleEndian.Uint32(data[p:])))
	if n < 0 {
		n = -n
	}
	unique := int(int32(binary.LittleEndian.Uint32(data[p+4:])))
	// unique==0 is legal: every normal shares one quantized value, the bit-pack
	// is empty and the n-entry index table carries the run (observed on the
	// 451 sample).
	if n <= 0 || n > 50_000_000 || unique < 0 || unique > n+64 {
		return nil
	}
	var out []nsCand
	// F is 1..15, or the reader replaces a stored 0/>15 with 16.
	for _, f := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16} {
		end, ok := readBitsEnd(data, p+8, []byte{byte(f), byte(f), byte(f), 0}, unique)
		if !ok {
			continue
		}
		if unique >= n {
			out = append(out, nsCand{end, f})
			continue
		}
		if _, e2, err := DecodeIndexTable(data, end, n); err == nil {
			out = append(out, nsCand{e2, f})
		}
	}
	return out
}

// decodeNormalShort decodes a NormalSetShort(100) body at p given the precision
// flag F recovered by the end-anchored walk. Each component is an F-bit signed
// fixed-point value scaled to 16 bits (findings N88/N92,
// getNormalComponentsFromBitsArray@0xc221bd + readNormals@0xc222e4); the vector
// is normalized. Zero-length normals decode to the zero vector.
func decodeNormalShort(data []byte, p, f int) [][3]float64 {
	if p+8 > len(data) || f < 1 || f > 16 {
		return nil
	}
	n := int(int32(binary.LittleEndian.Uint32(data[p:])))
	if n < 0 {
		n = -n
	}
	unique := int(int32(binary.LittleEndian.Uint32(data[p+4:])))
	if n <= 0 || unique < 0 || unique > n+64 {
		return nil
	}
	bitsEnd, ok := readBitsEnd(data, p+8, []byte{byte(f), byte(f), byte(f), 0}, unique)
	if !ok {
		return nil
	}
	vals, _, err := ReadBits(data, p+8, []byte{byte(f), byte(f), byte(f), 0}, unique, 3*unique)
	if err != nil {
		return nil
	}
	table := make([]uint32, n)
	if unique >= n {
		for i := range table {
			table[i] = uint32(i)
		}
	} else {
		t, _, err := DecodeIndexTable(data, bitsEnd, n)
		if err != nil {
			return nil
		}
		for i := range table {
			table[i] = t[i]
		}
	}
	shift := uint(16 - f)
	out := make([][3]float64, n)
	for i := 0; i < n; i++ {
		k := int(table[i])
		if 3*k+2 >= len(vals) {
			continue
		}
		var v [3]float64
		norm := 0.0
		for c := 0; c < 3; c++ {
			v[c] = float64(int16(uint16(vals[3*k+c]) << shift))
			norm += v[c] * v[c]
		}
		if norm == 0 {
			continue
		}
		s := 1 / math.Sqrt(norm)
		out[i] = [3]float64{v[0] * s, v[1] * s, v[2] * s}
	}
	return out
}

// wcand is a walker state: the current stream position plus, when a
// NormalSetShort(100) child has been consumed, its body offset and precision
// flag F so its normals can be decoded later.
type wcand struct {
	pos, nsPos, nsF int
}

// childOptions expands one child slot: always the position unchanged (child
// absent), plus the consumed end when a nil envelope or an accepted-typed body
// is present.
func childOptions(data []byte, c wcand, e int, types ...int) []wcand {
	out := []wcand{c}
	p := c.pos
	if p >= e {
		return out
	}
	kind, tid, nxt := readEnvelope(data, p)
	if nxt > e {
		return out
	}
	switch kind {
	case envKNil, envKBackref:
		return append(out, wcand{pos: nxt, nsPos: c.nsPos, nsF: c.nsF})
	case envKNew:
		accept := false
		for _, t := range types {
			if tid == t {
				accept = true
				break
			}
		}
		if !accept {
			return out
		}
		switch tid {
		case 61:
			if np, ok := skipTexCoord(data, nxt); ok && np <= e {
				out = append(out, wcand{pos: np, nsPos: c.nsPos, nsF: c.nsF})
			}
		case 59:
			if np, ok := skipNormalFloat(data, nxt); ok && np <= e {
				out = append(out, wcand{pos: np, nsPos: c.nsPos, nsF: c.nsF})
			}
		case 100:
			for _, nc := range normalShortCandidates(data, nxt) {
				if nc.end <= e {
					out = append(out, wcand{pos: nc.end, nsPos: nxt, nsF: nc.f})
				}
			}
		case 58:
			if np, ok := skipColor(data, nxt); ok && np <= e {
				out = append(out, wcand{pos: np, nsPos: c.nsPos, nsF: c.nsF})
			}
		}
	}
	return out
}

func chainChild(data []byte, cur []wcand, e int, types ...int) []wcand {
	var out []wcand
	for _, c := range cur {
		out = append(out, childOptions(data, c, e, types...)...)
	}
	return out
}

// locateFacesDeterministic walks the four child slots from vsEnd and returns the
// vertexesPerLine/indexesPerLine pair that ends on the element boundary e, plus
// the element's decoded normals when a NormalSetShort(100) child is present
// (findings N74/N75/N87/N92). It replaces the blind search previously used by
// locateFaceArrays.
//
// The four slots are VertexSet (already consumed, leaving vsEnd), TexCoord,
// Normal, Color. Each slot may be absent, so the walker expands every
// combination of present/absent children and accepts only a parse whose index
// list terminates on the element boundary and whose per-face counts sum to the
// index count.
func locateFacesDeterministic(data []byte, vsEnd, e int) (perFace, idx []uint16, normals [][3]float64, ok bool) {
	cur := []wcand{{pos: vsEnd}}
	cur = chainChild(data, cur, e, 61)      // TexCoordSet
	cur = chainChild(data, cur, e, 59, 100) // NormalSetFloat / NormalSetShort
	cur = chainChild(data, cur, e, 58)      // ColorSet
	seen := map[int]bool{}
	for _, c := range cur {
		// The sub-object end may need a small alignment/padding adjustment; the
		// end-anchor plus sum(perFace)==len(idx) still rejects spurious parses.
		for _, q := range []int{c.pos, AlignUp(c.pos, 4), AlignUp(c.pos, 8), c.pos + 4, c.pos - 4} {
			if q < vsEnd || q > e || seen[q] {
				continue
			}
			seen[q] = true
			if pf, ix, ok := tryVPLIPL(data, q, e); ok {
				if c.nsPos > 0 && c.nsF > 0 {
					normals = decodeNormalShort(data, c.nsPos, c.nsF)
				}
				return pf, ix, normals, true
			}
		}
	}
	return nil, nil, nil, false
}

// tryVPLIPL reads vertexesPerLine + align4 + indexesPerLine at p and accepts it
// only when the index list terminates on the element boundary e and
// sum(perFace)==len(idx).
func tryVPLIPL(data []byte, p, e int) ([]uint16, []uint16, bool) {
	perFace, np, ok := tryVPL(data, p, e)
	if !ok {
		return nil, nil, false
	}
	ip := AlignUp(np, 4)
	idx, end, ok := tryIPL(data, ip, e)
	if !ok {
		return nil, nil, false
	}
	if end > e || end < e-16 {
		return nil, nil, false
	}
	sum := 0
	for _, c := range perFace {
		sum += int(c)
	}
	if sum == len(idx) && len(perFace) > 0 {
		return perFace, idx, true
	}
	return nil, nil, false
}
