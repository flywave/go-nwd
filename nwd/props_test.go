package nwd

import (
	"bytes"
	"testing"
)

func TestSchemaRoundTrip(t *testing.T) {
	schemas := []Schema{
		{
			Name:        "LcOaNode",
			DisplayName: "Node",
			Concepts:    []string{"Common"},
			Fields: []SchemaField{
				{ID: "Name", DisplayName: "Name", Type: FieldString, Concepts: []string{"Identity"}},
				{ID: "Volume", DisplayName: "Volume", Type: FieldDouble},
				{ID: "Id", DisplayName: "Id", Type: FieldGUID},
			},
		},
		{Name: "LcOaScene", DisplayName: "Scene", Fields: []SchemaField{
			{ID: "Author", Type: FieldString},
		}},
	}
	enc := EncodeSchemas(schemas)
	got, err := DecodeSchemas(enc)
	if err != nil {
		t.Fatalf("DecodeSchemas: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("schemas=%d want 2", len(got))
	}
	if got[0].Name != "LcOaNode" || len(got[0].Fields) != 3 {
		t.Errorf("schema0=%+v", got[0])
	}
	if got[0].Fields[1].Type != FieldDouble || got[0].Fields[1].TypeName != "double" {
		t.Errorf("field1=%+v", got[0].Fields[1])
	}
	if len(got[0].Fields[0].Concepts) != 1 || got[0].Fields[0].Concepts[0] != "Identity" {
		t.Errorf("field0 concepts=%v", got[0].Fields[0].Concepts)
	}
}

func TestAttributeDecode(t *testing.T) {
	w := NewObjectWriter()
	// TextAttribute(76): ModelBase + attrFlags + string
	w.BeginNew(76)
	w.modelBase("user", "Text Prop", "IfcLabel")
	w.u32(0x5) // attrFlags
	w.String("hello world")
	// GuidAttribute(180)
	w.BeginNew(180)
	w.modelBase("u2", "Id", "IfcGloballyUniqueId")
	w.u32(0)
	w.buf = append(w.buf, bytes.Repeat([]byte{0xAB}, 16)...)
	w.End()

	or := NewObjectReader(w.Bytes(), formatVersionGate)
	first, err := or.ReadObject()
	if err != nil {
		t.Fatalf("text attr: %v", err)
	}
	if first.Attribute == nil || first.Attribute.Kind != AttrText {
		t.Fatalf("attr0=%+v", first.Attribute)
	}
	if first.Attribute.Text != "hello world" || first.Attribute.AttrFlags != 0x5 {
		t.Errorf("text=%q flags=%#x", first.Attribute.Text, first.Attribute.AttrFlags)
	}
	if first.Attribute.ClassName != "IfcLabel" {
		t.Errorf("class=%q", first.Attribute.ClassName)
	}

	second, err := or.ReadObject()
	if err != nil {
		t.Fatalf("guid attr: %v", err)
	}
	if second.Attribute == nil || second.Attribute.Kind != AttrGUID {
		t.Fatalf("attr1=%+v", second.Attribute)
	}
	if len(second.Attribute.GUID) != 16 || second.Attribute.GUID[0] != 0xAB {
		t.Errorf("guid=%x", second.Attribute.GUID)
	}
}

func TestFieldTypeNames(t *testing.T) {
	cases := map[FieldType]string{
		FieldDouble:  "double",
		FieldGUID:    "guid",
		FieldInt32:   "int32",
		FieldBoolean: "boolean",
		FieldString:  "string",
		FieldStruct:  "struct",
		FieldVector:  "vector",
		FieldType(9): "unknown",
	}
	for ft, want := range cases {
		if got := ft.String(); got != want {
			t.Errorf("FieldType(%d)=%q want %q", ft, got, want)
		}
	}
}
