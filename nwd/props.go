package nwd

import (
	"fmt"
)

// FieldType mirrors NwSchemaFieldType (E1 NwSchemaTypes.h, findings N27).
type FieldType uint32

const (
	FieldDouble  FieldType = 0
	FieldGUID    FieldType = 1
	FieldInt32   FieldType = 2
	FieldBoolean FieldType = 3
	FieldString  FieldType = 4
	FieldStruct  FieldType = 20
	FieldVector  FieldType = 21
	FieldUnknown FieldType = 0xFFFF
)

func (t FieldType) String() string {
	switch t {
	case FieldDouble:
		return "double"
	case FieldGUID:
		return "guid"
	case FieldInt32:
		return "int32"
	case FieldBoolean:
		return "boolean"
	case FieldString:
		return "string"
	case FieldStruct:
		return "struct"
	case FieldVector:
		return "vector"
	default:
		return "unknown"
	}
}

// SchemaField is one CDA property field definition.
type SchemaField struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name,omitempty"`
	Type        FieldType `json:"type"`
	TypeName    string    `json:"type_name"`
	Concepts    []string  `json:"concepts,omitempty"`
}

// Schema is one CDA property schema.
type Schema struct {
	Name        string        `json:"name"`
	DisplayName string        `json:"display_name,omitempty"`
	Concepts    []string      `json:"concepts,omitempty"`
	Fields      []SchemaField `json:"fields,omitempty"`
}

// decodeStringList reads i32 count + count× readString (findings N27,
// readConcepts@0xcf8a48).
func (r *byteReader) decodeStringList() ([]string, error) {
	count, err := r.i32()
	if err != nil {
		return nil, err
	}
	if count < 0 || count > 1<<20 {
		return nil, fmt.Errorf("nwd: string list count %d invalid", count)
	}
	out := make([]string, 0, count)
	for i := int32(0); i < count; i++ {
		s, err := r.readString()
		if err != nil {
			return nil, fmt.Errorf("nwd: string[%d]: %w", i, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// DecodeSchemas decodes the CommonSchemas logical stream (findings N27):
//
//	i32 schemaCount
//	per schema: string name, string displayName, concepts, i32 fieldCount
//	per field:  string id, string displayName, u32 type, concepts
//
// Layout is fixture-pinned until real samples (U15).
func DecodeSchemas(data []byte) ([]Schema, error) {
	r := newBR(data)
	count, err := r.i32()
	if err != nil {
		return nil, fmt.Errorf("nwd: schema count: %w", err)
	}
	if count < 0 || count > 1<<20 {
		return nil, fmt.Errorf("nwd: schema count %d invalid", count)
	}
	schemas := make([]Schema, 0, count)
	for i := int32(0); i < count; i++ {
		var s Schema
		if s.Name, err = r.readString(); err != nil {
			return nil, fmt.Errorf("nwd: schema[%d] name: %w", i, err)
		}
		if s.DisplayName, err = r.readString(); err != nil {
			return nil, fmt.Errorf("nwd: schema[%d] display: %w", i, err)
		}
		if s.Concepts, err = r.decodeStringList(); err != nil {
			return nil, fmt.Errorf("nwd: schema[%d] concepts: %w", i, err)
		}
		fc, err := r.i32()
		if err != nil {
			return nil, fmt.Errorf("nwd: schema[%d] field count: %w", i, err)
		}
		if fc < 0 || fc > 1<<20 {
			return nil, fmt.Errorf("nwd: schema[%d] field count %d invalid", i, fc)
		}
		for j := int32(0); j < fc; j++ {
			var f SchemaField
			if f.ID, err = r.readString(); err != nil {
				return nil, fmt.Errorf("nwd: schema[%d] field[%d] id: %w", i, j, err)
			}
			if f.DisplayName, err = r.readString(); err != nil {
				return nil, fmt.Errorf("nwd: schema[%d] field[%d] display: %w", i, j, err)
			}
			ft, err := r.u32()
			if err != nil {
				return nil, fmt.Errorf("nwd: schema[%d] field[%d] type: %w", i, j, err)
			}
			f.Type = FieldType(ft)
			f.TypeName = f.Type.String()
			if f.Concepts, err = r.decodeStringList(); err != nil {
				return nil, fmt.Errorf("nwd: schema[%d] field[%d] concepts: %w", i, j, err)
			}
			s.Fields = append(s.Fields, f)
		}
		schemas = append(schemas, s)
	}
	return schemas, nil
}

// EncodeSchemas is the fixture-side inverse of DecodeSchemas.
func EncodeSchemas(schemas []Schema) []byte {
	var out []byte
	out = appendI32(out, int32(len(schemas)))
	for _, s := range schemas {
		out = appendString(out, s.Name)
		out = appendString(out, s.DisplayName)
		out = appendStringList(out, s.Concepts)
		out = appendI32(out, int32(len(s.Fields)))
		for _, f := range s.Fields {
			out = appendString(out, f.ID)
			out = appendString(out, f.DisplayName)
			out = appendU32(out, uint32(f.Type))
			out = appendStringList(out, f.Concepts)
		}
	}
	return out
}

func appendString(b []byte, s string) []byte {
	b = appendI32(b, int32(len(s)))
	b = append(b, s...)
	if pad := (4 - len(b)%4) % 4; pad != 0 {
		b = append(b, make([]byte, pad)...)
	}
	return b
}

func appendStringList(b []byte, list []string) []byte {
	b = appendI32(b, int32(len(list)))
	for _, s := range list {
		b = appendString(b, s)
	}
	return b
}

// AttributeKind enumerates decoded attribute object kinds.
type AttributeKind string

const (
	AttrName     AttributeKind = "name"
	AttrText     AttributeKind = "text"
	AttrURL      AttributeKind = "url"
	AttrProperty AttributeKind = "property"
	AttrBinary   AttributeKind = "binary"
	AttrGUID     AttributeKind = "guid"
	AttrUInt64   AttributeKind = "uint64"
	AttrPublish  AttributeKind = "publish"
)

// attrKindByType maps NwObjectType IDs to attribute kinds (findings N28).
var attrKindByType = map[int]AttributeKind{
	66:  AttrUInt64,
	70:  AttrName,
	76:  AttrText,
	79:  AttrURL,
	86:  AttrProperty,
	88:  AttrBinary,
	180: AttrGUID,
}

// Attribute is a decoded attribute object payload.
type Attribute struct {
	Kind      AttributeKind
	TypeID    int
	UserName  string
	ClassName string
	AttrFlags uint32
	Text      string
	Number    uint32
	U64       uint64
	GUID      []byte // 16 bytes
	Binary    []byte
	Nested    []*Object

	// PublishAttribute (type 92) fields, best-effort (U18).
	Title, Subject, Author, Publisher           string
	Copyright, PublishedFor, Comments, Keywords string
	Password                                    string
	ExplicitName                                string
}

// decodeAttribute reads the shared attribute prefix (ModelBase + u32
// attrFlags, findings N28) and the kind-specific value.
func (o *ObjectReader) decodeAttribute(obj *Object) (*Attribute, error) {
	kind, ok := attrKindByType[obj.TypeID]
	if !ok {
		return nil, fmt.Errorf("%w: attribute type %d", ErrUnsupportedType, obj.TypeID)
	}
	a := &Attribute{Kind: kind, TypeID: obj.TypeID}
	if err := o.decodeModelBase(obj); err != nil {
		return nil, err
	}
	a.UserName = obj.UserName
	if obj.ClassName != nil {
		a.ClassName = obj.ClassName.Name
	}
	flags, err := o.r.u32()
	if err != nil {
		return nil, err
	}
	a.AttrFlags = flags

	switch kind {
	case AttrText:
		a.Text, err = o.r.readString()
	case AttrURL:
		if a.Text, err = o.r.readString(); err == nil {
			a.Number, err = o.r.u32()
		}
	case AttrName:
		a.Text, err = o.r.readString()
	case AttrUInt64:
		a.U64, err = o.r.u64()
	case AttrBinary:
		var n int32
		if n, err = o.r.i32(); err == nil {
			if n < 0 {
				err = fmt.Errorf("nwd: binary attribute negative length %d", n)
			} else {
				a.Binary, err = o.r.raw(int(n))
			}
		}
	case AttrGUID:
		a.GUID, err = o.r.raw(16)
	case AttrProperty:
		if a.Text, err = o.r.readString(); err == nil {
			if a.Number, err = o.r.u32(); err != nil {
				break
			}
			for i := 0; i < 2; i++ {
				var nested *Object
				if nested, err = o.ReadObject(); err != nil {
					break
				}
				if nested != nil {
					a.Nested = append(a.Nested, nested)
				}
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("nwd: attribute %s: %w", kind, err)
	}
	obj.Attribute = a
	return a, nil
}

func (r *byteReader) u64() (uint64, error) {
	b, err := r.raw(8)
	if err != nil {
		return 0, err
	}
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56, nil
}
