package nwd

// Instance placement from the fragments stream (findings N104/N106/N108/N109).
//
// Each fragment references one geometry element (GeomIndex, 1-based) and may
// carry a placement transform. Under NWD's shared display-pool model an
// element's face indices are NOT confined to its own VertexSet (finding N107),
// so a fragment cannot be re-meshed as a self-contained instance; the pair
// (transform, element) is exposed as placement metadata instead.

// Instance is one fragment's placement of a geometry element.
type Instance struct {
	ElementIndex int // 0-based index into the geometry stream's element list
	Transform    *Transform
	LocalMin     [3]float32 // element local bbox (equals the ref bbox, N106)
	LocalMax     [3]float32
}

// BuildInstances pairs each fragment that carries both a transform and a
// geometry reference with the referenced element.
func BuildInstances(fragments []FragmentRecord, elements []ElementGeometry) []Instance {
	var out []Instance
	for _, r := range fragments {
		ei := r.GeomElementIndex()
		if r.Transform == nil || ei < 0 || ei >= len(elements) {
			continue
		}
		out = append(out, Instance{
			ElementIndex: ei,
			Transform:    r.Transform,
			LocalMin:     r.RefMin,
			LocalMax:     r.RefMax,
		})
	}
	return out
}
