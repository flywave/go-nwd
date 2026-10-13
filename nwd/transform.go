package nwd

import (
	"fmt"
	"math"
)

// TransformKind identifies placement object types (findings N32).
type TransformKind string

const (
	TransformTranslation  TransformKind = "translation"
	TransformTransRot     TransformKind = "translation-rotation"
	TransformTransRotScale TransformKind = "translation-rotation-scale"
	TransformMatrix       TransformKind = "matrix"
)

// transformKindByType maps NwObjectType IDs to transform kinds.
var transformKindByType = map[int]TransformKind{
	14: TransformTranslation,
	15: TransformTransRot,
	16: TransformTransRotScale,
	17: TransformMatrix,
}

// Transform is a decoded placement (E2 Obj{Translation,TransRot,
// TransRotScale,Matrix}Reader, findings N32). Each readElement begins with
// alignPointer then the typed payload:
//
//	14: rd3Doubles (translation)
//	15: rd3Doubles + quaternion (4 doubles)
//	16: rd3Doubles + quaternion + f64 scale
//	17: element-wise f32 4x4 matrix
type Transform struct {
	Kind        TransformKind
	Translation [3]float64
	// Rotation is a quaternion (x,y,z,w) for kinds 15/16.
	Rotation [4]float64
	Scale    float64
	// Matrix is a 4x4 row-major matrix for kind 17.
	Matrix [16]float64
	HasMatrix bool
}

// decodeTransform reads a transform payload (findings N32).
func (o *ObjectReader) decodeTransform(obj *Object) (*Transform, error) {
	kind, ok := transformKindByType[obj.TypeID]
	if !ok {
		return nil, fmt.Errorf("%w: transform type %d", ErrUnsupportedType, obj.TypeID)
	}
	// alignPointer() before the payload (readElement prologue).
	o.r.align(8)
	t := &Transform{Kind: kind}
	switch kind {
	case TransformTranslation:
		tr, err := o.r.read3Doubles()
		if err != nil {
			return nil, err
		}
		t.Translation = tr
	case TransformTransRot:
		tr, err := o.r.read3Doubles()
		if err != nil {
			return nil, err
		}
		t.Translation = tr
		if t.Rotation, err = o.r.readQuaternion(); err != nil {
			return nil, err
		}
	case TransformTransRotScale:
		tr, err := o.r.read3Doubles()
		if err != nil {
			return nil, err
		}
		t.Translation = tr
		if t.Rotation, err = o.r.readQuaternion(); err != nil {
			return nil, err
		}
		if t.Scale, err = o.r.f64(); err != nil {
			return nil, err
		}
	case TransformMatrix:
		// 4x4 element-wise f32 (row-major; count pinned by samples, U17).
		for i := 0; i < 16; i++ {
			f, err := o.r.f32()
			if err != nil {
				return nil, err
			}
			t.Matrix[i] = float64(f)
		}
		t.HasMatrix = true
	}
	obj.Transform = t
	return t, nil
}

func (r *byteReader) read3Doubles() ([3]float64, error) {
	var v [3]float64
	for i := 0; i < 3; i++ {
		d, err := r.f64()
		if err != nil {
			return v, err
		}
		v[i] = d
	}
	return v, nil
}

func (r *byteReader) readQuaternion() ([4]float64, error) {
	var q [4]float64
	for i := 0; i < 4; i++ {
		d, err := r.f64()
		if err != nil {
			return q, err
		}
		q[i] = d
	}
	return q, nil
}

func (r *byteReader) f64() (float64, error) {
	b, err := r.raw(8)
	if err != nil {
		return 0, err
	}
	return math.Float64frombits(uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56), nil
}

func (r *byteReader) f32() (float32, error) {
	b, err := r.raw(4)
	if err != nil {
		return 0, err
	}
	return math.Float32frombits(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24), nil
}

// Matrix4 returns the 4x4 matrix form of the transform, composing
// translation/rotation/scale or returning the stored matrix (kind 17).
func (t *Transform) Matrix4() [16]float64 {
	if t.HasMatrix {
		return t.Matrix
	}
	// Rotation quaternion (x,y,z,w) → row-major 3x3.
	x, y, z, w := t.Rotation[0], t.Rotation[1], t.Rotation[2], t.Rotation[3]
	if x == 0 && y == 0 && z == 0 && w == 0 {
		x, y, z, w = 0, 0, 0, 1 // identity when absent
	}
	s := t.Scale
	if s == 0 {
		s = 1
	}
	xx, yy, zz := x*x, y*y, z*z
	xy, xz, yz := x*y, x*z, y*z
	wx, wy, wz := w*x, w*y, w*z
	return [16]float64{
		s * (1 - 2*(yy+zz)), s * 2 * (xy - wz), s * 2 * (xz + wy), 0,
		s * 2 * (xy + wz), s * (1 - 2*(xx+zz)), s * 2 * (yz - wx), 0,
		s * 2 * (xz - wy), s * 2 * (yz + wx), s * (1 - 2*(xx+yy)), 0,
		t.Translation[0], t.Translation[1], t.Translation[2], 1,
	}
}

// WriteTransform writes a transform payload after an envelope header
// (fixture-side inverse; aligns to 8 first).
func (w *ObjectWriter) WriteTransformPayload(t *Transform) {
	for (len(w.buf))%8 != 0 {
		w.buf = append(w.buf, 0)
	}
	switch t.Kind {
	case TransformTranslation:
		w.doubles(t.Translation[:])
	case TransformTransRot:
		w.doubles(t.Translation[:])
		w.doubles(t.Rotation[:])
	case TransformTransRotScale:
		w.doubles(t.Translation[:])
		w.doubles(t.Rotation[:])
		w.f64(t.Scale)
	case TransformMatrix:
		for _, v := range t.Matrix {
			w.f32(float32(v))
		}
	}
}

func (w *ObjectWriter) f64(v float64) {
	var b [8]byte
	bits := math.Float64bits(v)
	for i := 0; i < 8; i++ {
		b[i] = byte(bits >> (8 * i))
	}
	w.buf = append(w.buf, b[:]...)
}

func (w *ObjectWriter) f32(v float32) {
	var b [4]byte
	bits := math.Float32bits(v)
	for i := 0; i < 4; i++ {
		b[i] = byte(bits >> (8 * i))
	}
	w.buf = append(w.buf, b[:]...)
}

func (w *ObjectWriter) doubles(vs []float64) {
	for _, v := range vs {
		w.f64(v)
	}
}
