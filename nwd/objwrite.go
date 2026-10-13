package nwd

import (
	"encoding/binary"
)

// ObjectWriter emits the object-envelope stream grammar used by the
// go-nwd fixture builders (inverse of ObjectReader; see findings N19–N22).
type ObjectWriter struct {
	buf   []byte
	count int
}

// NewObjectWriter creates an empty stream writer.
func NewObjectWriter() *ObjectWriter { return &ObjectWriter{} }

// Bytes returns the encoded stream.
func (w *ObjectWriter) Bytes() []byte { return w.buf }

func (w *ObjectWriter) u32(v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

func (w *ObjectWriter) i32(v int32) { w.u32(uint32(v)) }

// String writes the readString<align0> form: i32 len, UTF-8 bytes, then
// pad to a 4-byte boundary (findings N37).
func (w *ObjectWriter) String(s string) {
	w.i32(int32(len(s)))
	w.buf = append(w.buf, s...)
	if pad := (4 - len(w.buf)%4) % 4; pad != 0 {
		w.buf = append(w.buf, make([]byte, pad)...)
	}
}

// BeginNew writes a new-object envelope header for the next vector slot.
func (w *ObjectWriter) BeginNew(typeID int) {
	w.u32(uint32(envNewBase + w.count))
	w.u32(uint32(typeID))
	w.count++
}

// WriteNil writes the nil terminator.
func (w *ObjectWriter) WriteNil() { w.u32(envNil) }

// WriteBackref writes a back-reference to vector slot idx.
func (w *ObjectWriter) WriteBackref(idx int) {
	w.u32(envBackref)
	w.i32(int32(idx))
}

// Name writes a type-52 Name payload (header included).
func (w *ObjectWriter) Name(display, name string) {
	w.BeginNew(TypeName)
	w.String(display)
	w.String(name)
}

// modelBase writes [userName][className object] using a nested Name.
func (w *ObjectWriter) modelBase(userName, classDisplay, className string) {
	w.String(userName)
	w.Name(classDisplay, className)
}

// modelItem writes the middle layer: base + flags + guidIndex + attrs.
func (w *ObjectWriter) modelItem(userName, classDisplay, className string, flags, guid uint32, attrCount uint32) {
	w.modelBase(userName, classDisplay, className)
	w.u32(flags)
	w.u32(guid)
	w.u32(attrCount)
}

// PartitionNode writes a type-32 node: modelType + modelItem +
// childCount/children + usage.
func (w *ObjectWriter) PartitionNode(userName, classDisplay, className string, modelType, flags, guid uint32, childCount uint32, usage int32, writeChildren func(*ObjectWriter)) {
	w.BeginNew(PartitionNode)
	w.u32(modelType)
	w.modelItem(userName, classDisplay, className, flags, guid, 0)
	w.u32(childCount)
	if writeChildren != nil {
		writeChildren(w)
	}
	w.i32(usage)
}

// GroupNode writes a type-53 node with childCount children written by fn.
func (w *ObjectWriter) GroupNode(userName, classDisplay, className string, flags, guid uint32, childCount uint32, writeChildren func(*ObjectWriter)) {
	w.BeginNew(GroupModelItemNode)
	w.modelItem(userName, classDisplay, className, flags, guid, 0)
	w.u32(childCount)
	if writeChildren != nil {
		writeChildren(w)
	}
}

// End writes the trailing nil marker (stream terminator).
func (w *ObjectWriter) End() { w.WriteNil() }
