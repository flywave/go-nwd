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
	AttrMaterial AttributeKind = "material"
	// AttrTransform marks the transform-carrying attribute types
	// 39/40/41 (TransformAttribute/TransAttribute/TransRotationAttribute).
	AttrTransform AttributeKind = "transform"
	// AttrGraphicMaterial marks typeID 200 (OdNwGraphicMaterialAttribute):
	// a shared-node index (fv>=451) or nested bundle object.
	AttrGraphicMaterial AttributeKind = "graphic-material"
)

// attrKindByType maps NwObjectType IDs to attribute kinds (findings N28).
// Type 31 MaterialAttribute added per readElement@0xc4242c (U19/U16 work).
var attrKindByType = map[int]AttributeKind{
	31:  AttrMaterial,
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

	// PublishAttribute (type 92) fields.
	Title, Subject, Author, Publisher           string
	Copyright, PublishedFor, Comments, Keywords string
	Password                                    string
	ExplicitName                                string
	PublishDate, ExpiryDate                     int64

	// MaterialAttribute (type 31) fields (readElement@0xc4242c: after the
	// attribute prefix, explicitName, align4, four DRGB colors as 3×f64,
	// then shininess and transparency as f64).
	Material *MaterialColor

	// Transform for the transform-carrying attribute types 39/40/41.
	Transform *Transform

	// PropertyAttribute (type 86) fields (real-file grammar, findings
	// N118): value string, then count × (key Name object + typed value).
	Props []PropertyField
}

// PropertyField is one key/typed-value pair of a PropertyAttribute.
type PropertyField struct {
	Key       string `json:"key"`
	FieldType int    `json:"field_type"` // NwSchemaFieldType (N27)
	Str       string `json:"str,omitempty"`
	Number    int64  `json:"num,omitempty"`
	GUID      []byte `json:"guid,omitempty"`
}

// MaterialColor carries an OdNwMaterialAttribute payload. Colors are the
// raw double RGB triplets as streamed (readDRGBColor = rd3Doubles).
type MaterialColor struct {
	Ambient      [3]float64
	Diffuse      [3]float64
	Specular     [3]float64
	Emissive     [3]float64
	Shininess    float64
	Transparency float64
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
	case AttrMaterial:
		// OdNwMaterialAttributeReader::readElement@0xc4242c: explicitName,
		// align4, ambient/diffuse/specular/emissive (readDRGBColor = 3×f64),
		// shininess, transparency (f64 each).
		if a.ExplicitName, err = o.r.readString(); err == nil {
			m := &MaterialColor{}
			o.r.align(8)
			for _, c := range []*[3]float64{&m.Ambient, &m.Diffuse, &m.Specular, &m.Emissive} {
				for j := 0; j < 3 && err == nil; j++ {
					var f float64
					if f, err = o.r.f64(); err == nil {
						c[j] = f
					}
				}
			}
			if err == nil {
				m.Shininess, err = o.r.f64()
			}
			if err == nil {
				m.Transparency, err = o.r.f64()
			}
			a.Material = m
		}
	case AttrProperty:
		// Real-file grammar (findings N118, BCCCH PartitionProps):
		// [attrFlags][u32 fieldCount][fieldCount × (key object +
		// NwSchemaFieldType + typed value)]. Replaces the fixture-era
		// "value string + 2×readObject" reading (N28).
		var n uint32
		if n, err = o.r.u32(); err != nil {
			break
		}
		if n > 1<<20 {
			err = fmt.Errorf("nwd: property field count %d exceeds limit", n)
			break
		}
		a.Number = n
		for i := uint32(0); i < n; i++ {
			keyObj, kerr := o.ReadObject()
			if kerr != nil {
				err = kerr
				break
			}
			f := PropertyField{}
			if keyObj != nil {
				if keyObj.TypeID == TypeName {
					f.Key = keyObj.DisplayName
					if f.Key == "" {
						f.Key = keyObj.Name
					}
				}
			}
			var ft int32
			if ft, err = o.r.i32(); err != nil {
				break
			}
			f.FieldType = int(ft)
			if err = o.readDataValue(&f); err != nil {
				break
			}
			a.Props = append(a.Props, f)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("nwd: attribute %s: %w", kind, err)
	}
	obj.Attribute = a
	return a, nil
}

// readDataValue decodes one OdNwObjectReaderManager::readData() typed
// value (readData@0xc3bd6e): [NwDataType enum][typed payload] — E1
// NwDataType.h: 1 DOUBLE, 2 INT32, 3 BOOL, 4 DISPLAY_STRING, 5 DATETIME,
// 6 DOUBLE_LENGTH, 7 DOUBLE_ANGLE, 8 NAME, 9 IDENTIFIER_STRING,
// 10 DOUBLE_AREA, 11 DOUBLE_VOLUME, 12 POINT3D, 13 POINT2D, 14 UINT32,
// 15 INT64, 16 UINT64. Floating-point cases begin with align8 and carry a
// trailing i32 unit/variant tag (12-byte form, real-file verified).
func (o *ObjectReader) readDataValue(f *PropertyField) error {
	switch f.FieldType {
	case 1, 6, 7, 10, 11: // DOUBLE / length / angle / area / volume
		o.r.align(8)
		d, err := o.r.f64()
		if err != nil {
			return err
		}
		f.Number = int64(d)
		f.Str = fmt.Sprintf("%g", d)
	case 12: // POINT3D
		o.r.align(8)
		for j := 0; j < 3; j++ {
			if _, err := o.r.f64(); err != nil {
				return err
			}
		}
	case 13: // POINT2D
		o.r.align(8)
		for j := 0; j < 2; j++ {
			if _, err := o.r.f64(); err != nil {
				return err
			}
		}
	case 2, 3: // INT32, BOOL
		v, err := o.r.i32()
		if err != nil {
			return err
		}
		f.Number = int64(v)
	case 14: // UINT32
		v, err := o.r.u32()
		if err != nil {
			return err
		}
		f.Number = int64(v)
	case 15, 16, 5: // INT64, UINT64, DATETIME
		v, err := o.r.i64()
		if err != nil {
			return err
		}
		f.Number = v
	case 8: // NAME — a nested Name object (real-file verified, N118)
		keyObj, err := o.ReadObject()
		if err != nil {
			return err
		}
		if keyObj != nil {
			f.Str = keyObj.DisplayName
			if f.Str == "" {
				f.Str = keyObj.Name
			}
		}
	case 4, 9: // DISPLAY_STRING, IDENTIFIER_STRING
		s, err := o.r.readString()
		if err != nil {
			return err
		}
		f.Str = s
	case 0: // NONE — 8-byte zero payload (real-file aligned, N118)
		v, err := o.r.i64()
		if err != nil {
			return err
		}
		f.Number = v
	case 22: // object reference: i32 (negative = null), real-file N118
		v, err := o.r.i32()
		if err != nil {
			return err
		}
		f.Number = int64(v)
	default:
		lo := o.r.pos
		hi := lo + 32
		if hi > len(o.r.buf) {
			hi = len(o.r.buf)
		}
		return fmt.Errorf("nwd: property data type %d (key %q) unsupported at %d: % x", f.FieldType, f.Key, lo, o.r.buf[lo:hi])
	}
	return nil
}

func (r *byteReader) u64() (uint64, error) {
	b, err := r.raw(8)
	if err != nil {
		return 0, err
	}
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56, nil
}
