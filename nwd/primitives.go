package nwd

import "math"

// Analytic primitive tessellation (findings N83).
//
// BimNv defines a small set of analytic geometry elements besides the
// tessellated shells: OdNwGraphicCircleElement (104) and
// OdNwGraphicCylinderElement (105). Their readers are simple fixed-layout
// records, and OdNwGeometry*Impl::toShell/toPolyline tessellate them with
// pointPowerOfTwo = 4 (16 segments), a fan for the circle and side+caps for the
// cylinder. go-nwd mirrors that here so primitives reach the exported mesh.

// primSegments matches the SDK default (pointPowerOfTwo = 4 -> 2^4).
const primSegments = 16

func readF32x3(b []byte, o int) [3]float64 {
	return [3]float64{float64(f32at(b, o)), float64(f32at(b, o+4)), float64(f32at(b, o+8))}
}

func norm3(v [3]float64) [3]float64 {
	l := math.Sqrt(v[0]*v[0] + v[1]*v[1] + v[2]*v[2])
	if l == 0 {
		return v
	}
	return [3]float64{v[0] / l, v[1] / l, v[2] / l}
}

// circleRing returns n points of a circle/ellipse centered at center in the
// plane spanned by unit axes u, v with radius r.
func circleRing(center, u, v [3]float64, r float64, n int) [][3]float64 {
	pts := make([][3]float64, n)
	for i := 0; i < n; i++ {
		th := 2 * math.Pi * float64(i) / float64(n)
		c, s := math.Cos(th), math.Sin(th)
		pts[i] = [3]float64{
			center[0] + r*(c*u[0]+s*v[0]),
			center[1] + r*(c*u[1]+s*v[1]),
			center[2] + r*(c*u[2]+s*v[2]),
		}
	}
	return pts
}

// decodeCircleElement reads an OdNwGraphicCircleElement payload (after the
// marker+type) and tessellates it into a filled disc (SDK toShell).
func decodeCircleElement(b []byte, o int) (verts [][3]float64, tris [][3]uint32, ok bool) {
	// [i32 flags][f32x3 origin][f32x3 xVector][f32x3 yVector][f32 radius]
	if o+44 > len(b) {
		return nil, nil, false
	}
	origin := readF32x3(b, o+4)
	xv := readF32x3(b, o+16)
	yv := readF32x3(b, o+28)
	r := float64(f32at(b, o+40))
	if r <= 0 {
		return nil, nil, false
	}
	ring := circleRing(origin, norm3(xv), norm3(yv), r, primSegments)
	for i := 1; i+1 < len(ring); i++ {
		tris = append(tris, [3]uint32{0, uint32(i), uint32(i + 1)})
	}
	return ring, tris, true
}

// decodeCylinderElement reads an OdNwGraphicCylinderElement payload and
// tessellates it into a capped cylinder (SDK toShell).
func decodeCylinderElement(b []byte, o int) (verts [][3]float64, tris [][3]uint32, ok bool) {
	// [i32 flags][f32x3 bottom][f32x3 top][f32x3 xAxis][f32x3 yAxis][f32 radius]
	if o+56 > len(b) {
		return nil, nil, false
	}
	bottom := readF32x3(b, o+4)
	top := readF32x3(b, o+16)
	xa := readF32x3(b, o+28)
	ya := readF32x3(b, o+40)
	r := float64(f32at(b, o+52))
	if r <= 0 {
		return nil, nil, false
	}
	n := primSegments
	u, v := norm3(xa), norm3(ya)
	br := circleRing(bottom, u, v, r, n)
	tr := circleRing(top, u, v, r, n)
	verts = make([][3]float64, 0, 2*n)
	verts = append(verts, br...)
	verts = append(verts, tr...)
	// side quads
	for i := 0; i < n; i++ {
		j := (i + 1) % n
		b0, b1 := uint32(i), uint32(j)
		t0, t1 := uint32(n+i), uint32(n+j)
		tris = append(tris, [3]uint32{b0, b1, t1}, [3]uint32{b0, t1, t0})
	}
	// caps (polygon fan), opposite winding
	for i := 1; i+1 < n; i++ {
		tris = append(tris, [3]uint32{0, uint32(i + 1), uint32(i)})                 // bottom
		tris = append(tris, [3]uint32{uint32(n), uint32(n + i), uint32(n + i + 1)}) // top
	}
	return verts, tris, true
}

// primitiveElement builds an ElementGeometry from a tessellated primitive by
// expressing its triangles as identity indices (faces of 3).
func primitiveElement(start, end, typ int, verts [][3]float64, tris [][3]uint32) ElementGeometry {
	el := ElementGeometry{Start: start, End: end, ElementType: typ, Vertices: verts}
	if len(tris) > 0 {
		el.PerFace = make([]uint16, len(tris))
		el.Indices = make([]uint16, 0, len(tris)*3)
		for i, t := range tris {
			el.PerFace[i] = 3
			el.Indices = append(el.Indices, uint16(t[0]), uint16(t[1]), uint16(t[2]))
		}
		el.FacesFound = true
	}
	return el
}
