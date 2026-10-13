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
// i32 byteLen, byteLen UTF-8 bytes, then pad to a 4-byte boundary. Verified
// against a real NWD: the padding sits after the bytes (e.g. a 39-byte name
// consumed at offset 16 ends at 55 and is padded to 56).
func (r *byteReader) readString() (string, error) {
	n, err := r.i32()
	if err != nil {
		return "", err
	}
	if n < 0 {
		return "", fmt.Errorf("nwd: negative string length %d", n)
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
		return nil, nil
	case marker == envBackref:
		idx, err := o.r.i32()
		if err != nil {
			return nil, err
		}
		if int(idx) < 0 || int(idx) >= len(o.vector) {
			return nil, fmt.Errorf("nwd: backref index %d out of range (%d)", idx, len(o.vector))
		}
		// Return a clone marker pointing at the slot; semantic fields are
		// carried by the original object entry recorded in Refs.
		return &Object{Index: int(idx), TypeID: -1, TypeName: "<backref>"}, nil
	case marker >= envNewBase:
		index := int(marker) - envNewBase
		if index != len(o.vector) {
			return nil, fmt.Errorf("nwd: new-object marker %d implies index %d but vector is %d",
				marker, index, len(o.vector))
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
		return nil, fmt.Errorf("nwd: invalid envelope marker %d", marker)
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
	case GroupModelItemNode, TypeGeometryModelItem:
		return o.decodeGroupNode(obj)
	default:
		if _, ok := attrKindByType[obj.TypeID]; ok {
			_, err := o.decodeAttribute(obj)
			return err
		}
		if _, ok := transformKindByType[obj.TypeID]; ok {
			_, err := o.decodeTransform(obj)
			return err
		}
		return fmt.Errorf("%w: type %d (%s)", ErrUnsupportedType, obj.TypeID, obj.TypeName)
	}
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

// decodeModelBase reads the shared node prefix (findings N22):
// [string userName][object className]. Gate formatVersion>21 is applied
// by the caller-set FormatVersion; values ≤21 are rejected by OpenTree
// as U10 low-version paths.
func (o *ObjectReader) decodeModelBase(obj *Object) error {
	if o.FormatVersion <= 21 {
		return fmt.Errorf("nwd: format version %d ≤ 21 unsupported (U10)", o.FormatVersion)
	}
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

// decodeModelItem reads the ModelItemNode middle layer (findings N22):
// flags u32, [version-gated], guidIndex u32, attrCount u32, attrs.
// The v>248 gated branch is skipped for now (U10) — FormatVersion is
// required to be in (21, 248] for this path.
func (o *ObjectReader) decodeModelItem(obj *Object) error {
	if err := o.decodeModelBase(obj); err != nil {
		return err
	}
	flags, err := o.r.u32()
	if err != nil {
		return err
	}
	obj.Flags = flags
	if o.FormatVersion > 248 {
		return fmt.Errorf("nwd: format version %d > 248 gated path unimplemented (U10)", o.FormatVersion)
	}
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
		if attr == nil {
			break
		}
		obj.Attributes = append(obj.Attributes, attr)
	}
	return nil
}

// decodePartitionNode reads typeID 32 (findings N22 §PartitionNode):
// u32 modelType, ModelItem middle, childCount+children, trailing usage
// enum i32. Child placement between base and usage matches the traced
// getChildren/readEnum order in PartitionNodeReader@0xc47641–0xc478c2
// (fixture-pinned until real samples, U10).
func (o *ObjectReader) decodePartitionNode(obj *Object) error {
	mt, err := o.r.u32()
	if err != nil {
		return err
	}
	obj.ModelType = &mt
	if err := o.decodeModelItem(obj); err != nil {
		return err
	}
	if err := o.decodeChildren(obj); err != nil {
		return err
	}
	usage, err := o.r.i32()
	if err != nil {
		return err
	}
	obj.Usage = &usage
	return nil
}

// decodeChildren reads u32 childCount followed by that many objects.
func (o *ObjectReader) decodeChildren(obj *Object) error {
	cc, err := o.r.u32()
	if err != nil {
		return err
	}
	if cc > 1<<20 {
		return fmt.Errorf("nwd: child count %d exceeds limit", cc)
	}
	for i := uint32(0); i < cc; i++ {
		child, err := o.ReadObject()
		if err != nil {
			return err
		}
		if child == nil {
			break
		}
		obj.Children = append(obj.Children, child)
	}
	return nil
}

// decodeGroupNode reads typeID 53/22: ModelItem middle plus children.
func (o *ObjectReader) decodeGroupNode(obj *Object) error {
	if err := o.decodeModelItem(obj); err != nil {
		return err
	}
	return o.decodeChildren(obj)
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
