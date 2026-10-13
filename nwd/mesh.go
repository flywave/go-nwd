package nwd

// SceneMesh is a triangulated geometry buffer reconstructed from a geometry stream.
type SceneMesh struct {
	Vertices  [][3]float64
	Normals   [][3]float64 // per-vertex normals from NormalSet children, if any
	Triangles [][3]uint32  // indices into Vertices
	Lines     [][2]uint32
	Points    []uint32
}

// DecodeMesh reconstructs triangles/lines/points from the geometry stream.
//
// Findings N71/N77/N79: geometry elements each carry a VertexSet whose vertices
// are appended to a single accumulating vertex pool. An element's indices are
// relative to that element's base offset in the pool (verified empirically:
// resolving them this way yields an average edge length ~10x smaller than an
// absolute interpretation).
//
// Faces are expanded exactly as the SDK does (findings N85,
// OdNwGeometryShellImpl::createTriangleFaces@0x10e1776): each face is a
// triangle strip. For a face with vertices p[0..n-1] the k-th triangle
// (k = 0..n-3) is (p[k], p[k+1], p[k+2]) for even k and (p[k+1], p[k], p[k+2])
// for odd k — the rolling-window traversal the binary performs. Open lines are
// emitted as segments.
func DecodeMesh(stream []byte, limit int) *SceneMesh {
	els := DecodeElements(stream, limit)
	m := &SceneMesh{}
	// First pass: assign pool bases.
	bases := make([]int, len(els))
	for i, e := range els {
		bases[i] = len(m.Vertices)
		m.Vertices = append(m.Vertices, e.Vertices...)
		for j := range e.Vertices {
			if j < len(e.Normals) {
				m.Normals = append(m.Normals, e.Normals[j])
			} else {
				m.Normals = append(m.Normals, [3]float64{})
			}
		}
	}
	// Second pass: resolve faces against the accumulating pool.
	n := len(m.Vertices)
	for i, e := range els {
		if !e.FacesFound {
			continue
		}
		base := bases[i]
		switch e.ElementType {
		case 94, 104, 105: // TriangleSet / Circle / Cylinder: triangle-strip expansion
			face := 0
			for _, c := range e.PerFace {
				fs := int(c)
				if fs < 3 || face+fs > len(e.Indices) {
					break
				}
				for _, tri := range StripTriangles(e.Indices[face : face+fs]) {
					a, b, d := base+int(tri[0]), base+int(tri[1]), base+int(tri[2])
					if a < n && b < n && d < n {
						m.Triangles = append(m.Triangles, [3]uint32{uint32(a), uint32(b), uint32(d)})
					}
				}
				face += fs
			}
		case 96: // PointSet
			face := 0
			for _, c := range e.PerFace {
				fs := int(c)
				if fs < 1 || face+fs > len(e.Indices) {
					break
				}
				for k := 0; k < fs; k++ {
					if gi := base + int(e.Indices[face+k]); gi < n {
						m.Points = append(m.Points, uint32(gi))
					}
				}
				face += fs
			}
		case 95: // LineSet: consecutive segments
			face := 0
			for _, c := range e.PerFace {
				fs := int(c)
				if fs < 2 || face+fs > len(e.Indices) {
					break
				}
				for k := 0; k+1 < fs; k++ {
					a := base + int(e.Indices[face+k])
					b := base + int(e.Indices[face+k+1])
					if a < n && b < n {
						m.Lines = append(m.Lines, [2]uint32{uint32(a), uint32(b)})
					}
				}
				face += fs
			}
		}
	}
	return m
}
