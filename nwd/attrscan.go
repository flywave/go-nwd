package nwd

import "encoding/binary"

// NameRecord is a Name object (typeID 52) found in a stream.
type NameRecord struct {
	Index       int    `json:"index"`
	DisplayName string `json:"display_name"`
	Name        string `json:"name"`
}

// ObjectKind is a lightweight envelope census entry.
type ObjectKind struct {
	Index  int    `json:"index"`
	TypeID int    `json:"type_id"`
	Type   string `json:"type"`
}

// ScanNames walks an object stream by its self-describing slot markers
// (new object at slot k has marker 100+k, findings N19) and extracts every
// Name object (typeID 52). Non-Name payloads are skipped by resynchronising
// on the next marker value, so this is a diagnostic extraction of names
// (property keys, class names) rather than a strict parser (U18).
func ScanNames(stream []byte, limit int) []NameRecord {
	var out []NameRecord
	r := newBR(stream)
	for slot := 0; slot < limit; slot++ {
		if !resyncToMarker(r, uint32(envNewBase+slot)) {
			break
		}
		if r.pos+8 > len(stream) {
			break
		}
		r.pos += 4 // consume marker
		typeID, err := r.u32()
		if err != nil {
			break
		}
		if typeID == TypeName {
			disp, _ := r.readString()
			nm, _ := r.readString()
			out = append(out, NameRecord{Index: slot, DisplayName: disp, Name: nm})
		}
	}
	return out
}

// ScanObjectKinds returns the typeID of each marker slot found.
func ScanObjectKinds(stream []byte, limit int) []ObjectKind {
	var out []ObjectKind
	r := newBR(stream)
	for slot := 0; slot < limit; slot++ {
		if !resyncToMarker(r, uint32(envNewBase+slot)) {
			break
		}
		if r.pos+8 > len(stream) {
			break
		}
		r.pos += 4
		typeID, err := r.u32()
		if err != nil {
			break
		}
		out = append(out, ObjectKind{Index: slot, TypeID: int(typeID), Type: ObjTypeName(int(typeID))})
	}
	return out
}

// resyncToMarker advances r.pos to the next occurrence of marker value m.
func resyncToMarker(r *byteReader, m uint32) bool {
	for i := r.pos; i+4 <= len(r.buf); i++ {
		if binary.LittleEndian.Uint32(r.buf[i:]) == m {
			r.pos = i
			return true
		}
	}
	return false
}
