package nwd

// Independent, reference-free validation of a reconstructed mesh (findings N97,
// plan battle E2). With no Navisworks/ODA renderer available to diff against,
// self-consistency invariants stand in: index coverage, degenerate-triangle
// fraction, and edge manifoldness. A pool-baseline error (U23) would show up as
// scrambled geometry — a high degenerate fraction and near-zero edge sharing.

// MeshStats summarizes geometric consistency of a SceneMesh.
type MeshStats struct {
	Vertices   int
	Triangles  int
	Lines      int
	Points     int
	Degenerate int // triangles with zero area (exact)
	Referenced int // vertices used by at least one triangle or line

	BoundaryEdges    int // edges used by exactly one triangle
	InteriorEdges    int // edges used by exactly two triangles
	NonManifoldEdges int // edges used by three or more triangles
}

// ValidateMesh computes consistency statistics for m.
func ValidateMesh(m *SceneMesh) MeshStats {
	st := MeshStats{
		Vertices:  len(m.Vertices),
		Triangles: len(m.Triangles),
		Lines:     len(m.Lines),
		Points:    len(m.Points),
	}
	used := make([]bool, len(m.Vertices))
	mark := func(i uint32) {
		if int(i) < len(used) {
			used[i] = true
		}
	}
	type edge struct{ a, b uint32 }
	edges := make(map[edge]int, len(m.Triangles)*3/2)
	addEdge := func(a, b uint32) {
		if a > b {
			a, b = b, a
		}
		edges[edge{a, b}]++
	}
	for _, t := range m.Triangles {
		mark(t[0])
		mark(t[1])
		mark(t[2])
		a, b, c := m.Vertices[t[0]], m.Vertices[t[1]], m.Vertices[t[2]]
		u := [3]float64{b[0] - a[0], b[1] - a[1], b[2] - a[2]}
		v := [3]float64{c[0] - a[0], c[1] - a[1], c[2] - a[2]}
		n := [3]float64{
			u[1]*v[2] - u[2]*v[1],
			u[2]*v[0] - u[0]*v[2],
			u[0]*v[1] - u[1]*v[0],
		}
		if n[0]*n[0]+n[1]*n[1]+n[2]*n[2] == 0 {
			st.Degenerate++
		}
		addEdge(t[0], t[1])
		addEdge(t[1], t[2])
		addEdge(t[2], t[0])
	}
	for _, e := range m.Lines {
		mark(e[0])
		mark(e[1])
	}
	for _, p := range m.Points {
		mark(p)
	}
	for _, u := range used {
		if u {
			st.Referenced++
		}
	}
	for _, c := range edges {
		switch {
		case c == 1:
			st.BoundaryEdges++
		case c == 2:
			st.InteriorEdges++
		default:
			st.NonManifoldEdges++
		}
	}
	return st
}
