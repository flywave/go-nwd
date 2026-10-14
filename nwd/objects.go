package nwd

import (
	"encoding/binary"
	"fmt"
)

// Object envelope constants (findings N19, readObject@0xc3b4b2).
const (
	envNil     = 0
	envBackref = 1
	envNewBase = 100 // new-object marker = 100 + vector index
)

// ObjectRef is one decoded object envelope reference.
type ObjectRef struct {
	// Kind: 0=nil, 1=backref, 2=new.
	Kind int
	// Index is the object-vector slot: for New it is marker-100; for
	// Backref the stream-provided index.
	Index int
	// TypeID is the NwObjectType of a New object.
	TypeID int
}

// ObjectReader walks an object stream using the readObject envelope
// grammar. It decodes typed payloads for the model-tree types and skips
// (records) unknown types only when no payload framing is possible —
// therefore unknown types abort the walk (U9: per-type readers queue).
type ObjectReader struct {
	r      *byteReader
	vector []ObjectRef
	// FormatVersion mirrors ObjectReaderManager+0x18 (findings N22);
	// gates documented in analysis/03-model-tree.md §6 (U10).
	FormatVersion uint32
	// LogicalStream selects the LogicalHierarchy-stream behaviour of
	// PartitionNode payloads (E2 readElement@0xc47582): the first
	// PartitionNode becomes the context root and reads no children;
	// subsequent ones read a child object vector. In Partition streams
	// (fv>27) PartitionNodes never read children (N57).
	LogicalStream bool
	logicalRoot   bool
}

// Gap records a skipped stream segment during a tolerant walk.
type Gap struct {
	Pos     int    `json:"pos"`
	Skipped int    `json:"skipped_bytes"`
	Err     string `json:"error"`
}

// resync advances past an undecodable segment to the next plausible
// envelope: any marker in [100, 4200] bound to a typeID <= 200. The marker
// sequence may run ahead of the local vector (addToObjectVector appends
// when the slot is out of range), so accept a wide window. Returns the
// number of bytes skipped (0 when no candidate remains).
func (o *ObjectReader) resync() int {
	for p := o.r.pos; p+8 <= len(o.r.buf); p++ {
		m := binary.LittleEndian.Uint32(o.r.buf[p:])
		if m < envNewBase || m > envNewBase+4100 {
			continue
		}
		if binary.LittleEndian.Uint32(o.r.buf[p+4:]) > 200 {
			continue
		}
		skip := p - o.r.pos
		o.r.pos = p
		return skip
	}
	o.r.pos = len(o.r.buf)
	return 0
}

type byteReader struct {
	buf []byte
	pos int
}

func newBR(b []byte) *byteReader { return &byteReader{buf: b} }

func (r *byteReader) u32() (uint32, error) {
	if r.pos+4 > len(r.buf) {
		return 0, fmt.Errorf("nwd: object stream truncated at %d", r.pos)
	}
	v := binary.LittleEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *byteReader) i32() (int32, error) {
	v, err := r.u32()
	return int32(v), err
}

func (r *byteReader) raw(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, fmt.Errorf("nwd: object stream truncated at %d (+%d)", r.pos, n)
	}
	b := r.buf[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

func (r *byteReader) align(a int) {
	if pad := r.pos % a; pad != 0 {
		r.pos += a - pad
	}
}

// readString decodes NwStreamCommon::readString<align0> (findings N21/N37):
// i32 byteLen, byteLen UTF-8 bytes, then pad to a 4-byte boundary. A
// negative byteLen denotes a null/unset string and consumes only the
// length field (verified against real NWD attribute payloads, N56).
func (r *byteReader) readString() (string, error) {
	n, err := r.i32()
	if err != nil {
		return "", err
	}
	if n < 0 {
		return "", nil
	}
	b, err := r.raw(int(n))
	if err != nil {
		return "", err
	}
	r.align(4)
	return string(b), nil
}

// Object is one fully decoded stream object.
type Object struct {
	Index    int // vector slot
	TypeID   int
	TypeName string

	// Name payload (TypeID 52).
	DisplayName string
	Name        string

	// ModelBase payload (nodes).
	UserName  string
	ClassName *Object // nested Name object (nil when marker=0)

	// ModelItemNode payload.
	Flags      uint32
	GuidIndex  uint32
	Attributes []*Object

	// ExplicitName trailing string (readExplisitName) on group / geometry
	// model items and material attributes (E2 readElement call order).
	ExplicitName string

	// PartitionNode payload.
	ModelType *uint32
	Usage     *int32

	// Attribute payload (when TypeID is an attribute type, M5).
	Attribute *Attribute

	// Transform payload (when TypeID is a placement type, M6).
	Transform *Transform

	// Children for group nodes (read by parent-side loop in real readers;
	// go-nwd collects explicit child objects attached during decode).
	Children []*Object
}

// ReadObject decodes one envelope record (findings N19).
func (o *ObjectReader) ReadObject() (*Object, error) {
	marker, err := o.r.u32()
	if err != nil {
		return nil, err
	}
	switch {
	case marker == envNil:
		// A nil occupies its object-vector slot too: readObjectVector
		// push_backs null entries (real-file backrefs address NIL slots,
		// findings N123).
		o.vector = append(o.vector, ObjectRef{Kind: 0, Index: len(o.vector)})
		return nil, nil
	case marker == envBackref:
		idx, err := o.r.i32()
		if err != nil {
			return nil, err
		}
		// The stored value is 100+slot (readObject subtracts 0x64 before
		// the bounds check, readObject@0xc3b526).
		slot := int(idx) - envNewBase
		if slot < 0 || slot >= len(o.vector) {
			return nil, fmt.Errorf("nwd: backref index %d out of range (%d)", idx, len(o.vector))
		}
		idx = int32(slot)
		// Return a clone marker pointing at the slot; semantic fields are
		// carried by the original object entry recorded in Refs.
		return &Object{Index: int(idx), TypeID: -1, TypeName: "<backref>"}, nil
	case marker >= envNewBase:
		// New object. The SDK does not require markers to be sequential:
		// addToObjectVector assigns slot marker-100 when it is inside the
		// vector, otherwise appends (readObject@0xc3b58d /
		// addToObjectVector@0xc3b416). go-nwd always appends and records
		// the stream slot.
		index := int(marker) - envNewBase
		if index < 0 || index > len(o.vector) {
			index = len(o.vector)
		}
		typeID, err := o.r.u32()
		if err != nil {
			return nil, err
		}
		obj := &Object{Index: index, TypeID: int(typeID), TypeName: ObjTypeName(int(typeID))}
		// Reserve the vector slot before decoding nested payloads: nested
		// envelopes may back-reference this object (C++ pushes the
		// placeholder before the factory runs, readObject@0xc3b67a).
		o.vector = append(o.vector, ObjectRef{Kind: 2, Index: index, TypeID: int(typeID)})
		if err := o.decodePayload(obj); err != nil {
			return nil, err
		}
		return obj, nil
	default:
		// Any other marker value is also a new object (the SDK only
		// special-cases 0=nil and 1=backref; addToObjectVector treats
		// marker-100 as an unsigned slot that appends when out of range).
		index := len(o.vector)
		if int(marker) >= envNewBase {
			index = int(marker) - envNewBase
			if index < 0 || index > len(o.vector) {
				index = len(o.vector)
			}
		}
		typeID, err := o.r.u32()
		if err != nil {
			return nil, err
		}
		obj := &Object{Index: index, TypeID: int(typeID), TypeName: ObjTypeName(int(typeID))}
		// Reserve the vector slot before decoding nested payloads: nested
		// envelopes may back-reference this object (C++ pushes the
		// placeholder before the factory runs, readObject@0xc3b67a).
		o.vector = append(o.vector, ObjectRef{Kind: 2, Index: index, TypeID: int(typeID)})
		if err := o.decodePayload(obj); err != nil {
			return nil, err
		}
		return obj, nil
	}
}

// decodePayload dispatches the typed payload after the envelope header.
// Model-tree types only; other types return ErrUnsupportedType so callers
// can census streams without full decoding (U9).
func (o *ObjectReader) decodePayload(obj *Object) error {
	switch obj.TypeID {
	case TypeName:
		return o.decodeName(obj)
	case PartitionNode:
		return o.decodePartitionNode(obj)
	case GroupModelItemNode:
		return o.decodeGroupNode(obj)
	case TypeGeometryModelItem:
		return o.decodeGeometryItem(obj)
	case 5, 18: // Name-grammar variants (N118: type 18 as property keys,
		// type 5 as tree child "Lines"/"LcRevitComposite")
		return o.decodeName(obj)
	case 23: // ModelItem-family node ("Site - Sidewalk(JOINTS)" layer
		// entries: userName + className backref + flags + guid +
		// attrCount + attrs, real-file walk findings N123)
		return o.decodeModelItem(obj)
	case TypeGraphicJsonBundle:
		return o.decodeGraphicJsonBundle(obj)
	case 196: // single-string Name variant ("Model Lines", N118); the
		// string pads to an 8-byte boundary (readString<align1>)
		s, err := o.r.readString()
		if err != nil {
			return err
		}
		obj.UserName = s
		o.r.align(8)
		return nil
	default:
		if kind, ok := transformAttrKindByType[obj.TypeID]; ok {
			err := o.decodeTransformAttribute(obj, kind)
			return err
		}
		if obj.TypeID == TypeGraphicMaterialAttribute {
			return o.decodeGraphicMaterialAttribute(obj)
		}
		if _, ok := attrKindByType[obj.TypeID]; ok {
			_, err := o.decodeAttribute(obj)
			return err
		}
		if _, ok := transformKindByType[obj.TypeID]; ok {
			_, err := o.decodeTransform(obj)
			return err
		}
		if obj.TypeID == TypePublishAttribute {
			return o.decodePublishAttribute(obj)
		}
		return fmt.Errorf("%w: type %d (%s) at %d", ErrUnsupportedType, obj.TypeID, obj.TypeName, o.r.pos)
	}
}

// decodeTransformAttribute reads the transform-carrying attribute types
// (real-file validated on BCCCH LogicalHierarchy, findings N117):
//
//	39 TransformAttribute:  explicitName, align8, DMatrix3d (12×f64),
//	                        u32 reverse, DVector3d (readElement@0xc4311e)
//	40 TransAttribute:      explicitName, align8, DVector3d translation
//	41 TransRotationAttr.:  align8, DVector3d translation, quaternion,
//	                        u32 tail (readElement@0xc437c2)
//
// The decoded placement is exposed as Attribute.Transform.
func (o *ObjectReader) decodeTransformAttribute(obj *Object, kind TransformKind) error {
	if err := o.decodeModelBase(obj); err != nil {
		return err
	}
	a := &Attribute{Kind: AttrTransform, TypeID: obj.TypeID, UserName: obj.UserName}
	if obj.ClassName != nil {
		a.ClassName = obj.ClassName.Name
	}
	flags, err := o.r.u32()
	if err != nil {
		return err
	}
	a.AttrFlags = flags
	t := &Transform{Kind: kind}
	switch obj.TypeID {
	case 39:
		if a.ExplicitName, err = o.r.readString(); err != nil {
			return err
		}
		o.r.align(8)
		var m [12]float64
		for i := range m {
			if m[i], err = o.r.f64(); err != nil {
				return err
			}
		}
		// OdGeMatrix3d row-major 3x4 → 4x4 (bottom row 0,0,0,1).
		t.Matrix = [16]float64{
			m[0], m[1], m[2], m[3],
			m[4], m[5], m[6], m[7],
			m[8], m[9], m[10], m[11],
			0, 0, 0, 1,
		}
		t.HasMatrix = true
		if _, err = o.r.u32(); err != nil {
			return err
		}
		if _, err = o.r.read3Doubles(); err != nil {
			return err
		}
	case 40:
		if a.ExplicitName, err = o.r.readString(); err != nil {
			return err
		}
		o.r.align(8)
		if t.Translation, err = o.r.read3Doubles(); err != nil {
			return err
		}
	case 41:
		o.r.align(8)
		if t.Translation, err = o.r.read3Doubles(); err != nil {
			return err
		}
		if t.Rotation, err = o.r.readQuaternion(); err != nil {
			return err
		}
		if _, err = o.r.u32(); err != nil {
			return err
		}
	}
	a.Transform = t
	obj.Attribute = a
	obj.Transform = t
	return nil
}

// transformAttrKindByType maps transform-carrying attribute types
// (E2 OdNwTransformAttributeReader@0xc4311e, OdNwTransAttributeReader,
// OdNwTransRotationAttributeReader).
var transformAttrKindByType = map[int]TransformKind{
	39: TransformMatrix,
	40: TransformTranslation,
	41: TransformTransRot,
}

// TypeGraphicMaterialAttribute is NwObjectType 200; its payload is the
// base attribute prefix plus a graphic JSON bundle — shared-node indexed
// for fv>=451 (readSharedObject@0xc3b76e), a full object envelope below.
const TypeGraphicMaterialAttribute = 200

// TypeGraphicJsonBundle is NwObjectType 185: a presenter-material JSON
// blob carried directly in the logical stream (readElement@0xc36af4).
const TypeGraphicJsonBundle = 185

// decodeGraphicJsonBundle reads typeID 185 (readElement@0xc36af4):
// [jsonData string][fv>446: materialJson string][tagged loop: u32 tag;
// tag==0 ends; else string name, u32 hasEmbedded, and when set an
// embedded file [string][string][align8][u64 len][len bytes]]
// [string xrefKey].
func (o *ObjectReader) decodeGraphicJsonBundle(obj *Object) error {
	a := &Attribute{Kind: AttrJsonBundle, TypeID: obj.TypeID}
	var err error
	if a.Text, err = o.r.readString(); err != nil {
		return err
	}
	if o.FormatVersion > 446 {
		a.ExplicitName, err = o.r.readString() // materialJson
		if err != nil {
			return err
		}
	}
	// Entry count (BCCCH: 8), then count-driven entries; each is
	// [string name][u32][u32 hasEmbedded] (real-file tiling, N122).
	var entryCount uint32
	if entryCount, err = o.r.u32(); err != nil {
		return err
	}
	if entryCount > 1<<20 {
		return fmt.Errorf("nwd: json bundle entry count %d exceeds limit", entryCount)
	}
	for i := uint32(0); i < entryCount; i++ {
		if _, err = o.r.readString(); err != nil { // entry name
			return err
		}
		if _, err = o.r.u32(); err != nil {
			return err
		}
		var hasEmbedded uint32
		if hasEmbedded, err = o.r.u32(); err != nil {
			return err
		}
		if hasEmbedded == 0 {
			continue
		}
		// readEmbeddedFile@0xc3c48a: two strings, align8, u64 length, bytes.
		if _, err = o.r.readString(); err != nil {
			return err
		}
		if _, err = o.r.readString(); err != nil {
			return err
		}
		o.r.align(8)
		var n int64
		if n, err = o.r.i64(); err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("nwd: embedded file negative length %d", n)
		}
		if n > 1<<30 {
			return fmt.Errorf("nwd: embedded file %d bytes exceeds limit", n)
		}
		if _, err = o.r.raw(int(n)); err != nil {
			return err
		}
	}
	if _, err = o.r.readString(); err != nil { // xref key
		return err
	}
	obj.Attribute = a
	return nil
}

// decodeGraphicMaterialAttribute reads typeID 200 (readElement@0xc43daa):
// base attribute prefix, then the graphic bundle by shared-node index
// (fv>=451) or as a nested envelope object.
func (o *ObjectReader) decodeGraphicMaterialAttribute(obj *Object) error {
	if err := o.decodeModelBase(obj); err != nil {
		return err
	}
	a := &Attribute{Kind: AttrGraphicMaterial, TypeID: obj.TypeID, UserName: obj.UserName}
	if obj.ClassName != nil {
		a.ClassName = obj.ClassName.Name
	}
	flags, err := o.r.u32()
	if err != nil {
		return err
	}
	a.AttrFlags = flags
	if o.FormatVersion > 451 {
		var idx int32
		if idx, err = o.r.i32(); err != nil {
			return err
		}
		a.Number = uint32(idx)
	} else {
		nested, err := o.ReadObject()
		if err != nil {
			return err
		}
		if nested != nil {
			a.Nested = append(a.Nested, nested)
		}
	}
	obj.Attribute = a
	return nil
}

func (o *ObjectReader) decodeName(obj *Object) error {
	dn, err := o.r.readString()
	if err != nil {
		return err
	}
	obj.DisplayName = dn
	nm, err := o.r.readString()
	if err != nil {
		return err
	}
	obj.Name = nm
	return nil
}

// decodeModelBase reads the shared node prefix (findings N22/N56):
// [string userName][object className]. Verified against a real v451 NWD
// (DecodePartitionRoot); older-version layouts remain U10.
func (o *ObjectReader) decodeModelBase(obj *Object) error {
	un, err := o.r.readString()
	if err != nil {
		return err
	}
	obj.UserName = un
	cls, err := o.ReadObject()
	if err != nil {
		return err
	}
	obj.ClassName = cls
	return nil
}

// decodeModelItem reads the ModelItemNode middle layer (findings N22/N56):
// u32 flags, u32 guidIndex, u32 attrCount, then attrCount attribute
// objects. Verified against a real v451 NWD.
func (o *ObjectReader) decodeModelItem(obj *Object) error {
	if err := o.decodeModelBase(obj); err != nil {
		return err
	}
	flags, err := o.r.u32()
	if err != nil {
		return err
	}
	obj.Flags = flags
	gi, err := o.r.u32()
	if err != nil {
		return err
	}
	obj.GuidIndex = gi
	ac, err := o.r.u32()
	if err != nil {
		return err
	}
	if ac > 1<<16 {
		return fmt.Errorf("nwd: attribute count %d exceeds limit", ac)
	}
	for i := uint32(0); i < ac; i++ {
		attr, err := o.ReadObject()
		if err != nil {
			return err
		}
		// A nil slot (marker 0) is a valid empty entry; the count drives
		// the loop (readObjectVector pushes null entries too).
		obj.Attributes = append(obj.Attributes, attr)
	}
	return nil
}

// decodePartitionNode reads typeID 32 (real-file verified, findings N56):
// u32 modelType (fv>202; else 0), then the ModelItem middle (ModelBase +
// flags + guid + attrCount + attributes). Children follow only in the
// LogicalHierarchy stream (and the first node there is the context root,
// which reads none) or in fv<=27 Partition streams (readElement@0xc47582).
func (o *ObjectReader) decodePartitionNode(obj *Object) error {
	mt, err := o.r.u32()
	if err != nil {
		return err
	}
	obj.ModelType = &mt
	if err := o.decodeModelItem(obj); err != nil {
		return err
	}
	if o.LogicalStream {
		if !o.logicalRoot {
			o.logicalRoot = true
			return nil
		}
		return o.decodeChildren(obj)
	}
	return nil
}

// decodeGeometryItem reads typeID 22 (readElement@0xc42c5e): the ModelItem
// middle only — like type 53 the trailing explicit name is gated off at
// our format versions (findings N122). The fv<=30 path (align + bbox
// DPoint3d×2 + u32) applies to pre-2011 files only and is not
// implemented (U10).
func (o *ObjectReader) decodeGeometryItem(obj *Object) error {
	return o.decodeModelItem(obj)
}

// decodeChildren reads u32 childCount followed by that many objects.
func (o *ObjectReader) decodeChildren(obj *Object) error {
	cc, err := o.r.u32()
	if err != nil {
		return err
	}
	return o.decodeChildrenN(cc, obj)
}

// decodeChildrenN reads cc child objects (count-driven; nil slots valid).
func (o *ObjectReader) decodeChildrenN(cc uint32, obj *Object) error {
	if cc > 1<<20 {
		return fmt.Errorf("nwd: child count %d exceeds limit", cc)
	}
	for i := uint32(0); i < cc; i++ {
		child, err := o.ReadObject()
		if err != nil {
			return err
		}
		// nil slots are valid empty children (count-driven loop).
		obj.Children = append(obj.Children, child)
	}
	return nil
}

// decodeGroupNode reads typeID 53 (readElement@0xc3a216): the ModelItem
// middle and an inline child object vector. The SDK's trailing
// readExplisitName is version-gated and absent at the format versions in
// our samples (fv≈100/431/451, real-file walk findings N122); it becomes
// active only in newer files (U10 gate to pin).
//
// Children carry a recovery path (N123): the streamed attrCount can be
// one short of the real attribute sequence under the combined per-field
// gates, which makes the child count position decode as garbage. When the
// child vector fails, roll back, decode one more attribute and retry.
func (o *ObjectReader) decodeGroupNode(obj *Object) error {
	if err := o.decodeModelItem(obj); err != nil {
		return err
	}
	save := o.r.pos
	cc, err := o.r.u32()
	if err != nil {
		return err
	}
	if err := o.decodeChildrenN(cc, obj); err == nil {
		return nil
	}
	o.r.pos = save
	attr, aerr := o.ReadObject()
	if aerr != nil {
		o.r.pos = save
		return aerr
	}
	obj.Attributes = append(obj.Attributes, attr)
	cc, err = o.r.u32()
	if err != nil {
		return err
	}
	return o.decodeChildrenN(cc, obj)
}

// zstring reads a NUL-terminated string, advancing past the terminator and
// padding the position to a 4-byte boundary.
func (r *byteReader) zstring() (string, error) {
	start := r.pos
	for r.pos < len(r.buf) && r.buf[r.pos] != 0 {
		r.pos++
	}
	if r.pos >= len(r.buf) {
		return "", fmt.Errorf("nwd: unterminated string at %d", start)
	}
	s := string(r.buf[start:r.pos])
	r.pos++ // NUL
	r.align(4)
	return s, nil
}

// ErrUnsupportedType means the envelope type has no payload decoder yet.
var ErrUnsupportedType = fmt.Errorf("nwd: unsupported object type")

// Remaining reports unread bytes.
func (o *ObjectReader) Remaining() int { return len(o.r.buf) - o.r.pos }

// NewObjectReader creates a reader over a logical stream's raw bytes with
// the given format-version gate value (context+0x18 semantics).
func NewObjectReader(data []byte, formatVersion uint32) *ObjectReader {
	return &ObjectReader{r: newBR(data), FormatVersion: formatVersion}
}

// decodePublishAttribute reads typeID 92 (PublishAttribute) after the base
// Attribute prefix (E2 OdNwPublishAttributeReader::readElement@0xc58ffa,
// verified against the real NWD, findings N56):
//
//	[ModelBase: string userName + object Name]   (base attribute)
//	u32 attrFlags                                 (base attribute)
//	i32 publishFlags
//	string title, subject, author, publisher
//	align 8
//	i64 publishDate, expiryDate
//	string copyright, publishedFor, comments, keywords
//	string explicitName
func (o *ObjectReader) decodePublishAttribute(obj *Object) error {
	if err := o.decodeModelBase(obj); err != nil {
		return err
	}
	a := &Attribute{Kind: AttrPublish, TypeID: obj.TypeID, UserName: obj.UserName}
	if obj.ClassName != nil {
		a.ClassName = obj.ClassName.Name
	}
	attrFlags, err := o.r.u32()
	if err != nil {
		return err
	}
	a.AttrFlags = attrFlags
	pf, err := o.r.i32()
	if err != nil {
		return err
	}
	a.Number = uint32(pf)
	for _, fp := range []*string{&a.Title, &a.Subject, &a.Author, &a.Publisher} {
		s, err := o.r.readString()
		if err != nil {
			return err
		}
		*fp = s
	}
	o.r.align(8)
	ts := make([]int64, 2)
	for i := range ts {
		if ts[i], err = o.r.i64(); err != nil {
			return err
		}
	}
	a.PublishDate, a.ExpiryDate = ts[0], ts[1]
	for _, fp := range []*string{&a.Copyright, &a.PublishedFor, &a.Comments, &a.Keywords} {
		s, err := o.r.readString()
		if err != nil {
			return err
		}
		*fp = s
	}
	if nm, err := o.r.readString(); err == nil {
		a.ExplicitName = nm
	}
	obj.Attribute = a
	return nil
}

func (r *byteReader) i64() (int64, error) {
	b, err := r.raw(8)
	if err != nil {
		return 0, err
	}
	var v uint64
	for i := 0; i < 8; i++ {
		v |= uint64(b[i]) << (8 * i)
	}
	return int64(v), nil
}

// f64 is defined in transform.go (shared byteReader helper).
