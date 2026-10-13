package nwd

// SceneMesh is a triangulated geometry buffer reconstructed from a geometry stream.
type SceneMesh struct {
	Vertices  [][3]float64
	Triangles [][3]uint32 // indices into Vertices
	Lines     [][2]uint32
	Points    []uint32
}

// DecodeMesh reconstructs triangles/lines/points from the geometry stream.
//
// Findings N71/N77/N79: geometry elements each carry a VertexSet whose vertices
// are appended to a single accumulating vertex pool. An element's indices are
// relative to that element's base offset in the pool (verified empirically:
// resolving them this way yields an average edge length ~10x smaller than an
// absolute interpretation). Polygons (faces with >3 vertices) are fan
// triangulated; open lines are emitted as segments.
func DecodeMesh(stream []byte, limit int) *SceneMesh {
	els := DecodeElements(stream, limit)
	m := &SceneMesh{}
	// First pass: assign pool bases.
	bases := make([]int, len(els))
	for i, e := range els {
		bases[i] = len(m.Vertices)
		m.Vertices = append(m.Vertices, e.Vertices...)
	}
	// Second pass: resolve faces against the accumulating pool.
	n := len(m.Vertices)
	for i, e := range els {
		if !e.FacesFound {
			continue
		}
		base := bases[i]
		switch e.ElementType {
		case 94, 104, 105: // TriangleSet / Circle / Cylinder: polygons -> fan triangulation
			face := 0
			for _, c := range e.PerFace {
				fs := int(c)
				if fs < 3 || face+fs > len(e.Indices) {
					break
				}
				v0 := base + int(e.Indices[face])
				if v0 < n {
					for k := 1; k+1 < fs; k++ {
						v1 := base + int(e.Indices[face+k])
						v2 := base + int(e.Indices[face+k+1])
						if v1 < n && v2 < n {
							m.Triangles = append(m.Triangles, [3]uint32{uint32(v0), uint32(v1), uint32(v2)})
						}
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
