// Package nwio provides little-endian byte-reading primitives for the NWD
// container layer.
package nwio

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrShort is returned when fewer bytes remain than requested.
var ErrShort = errors.New("nwio: unexpected end of data")

// Reader reads little-endian integers and byte slices from an underlying
// byte slice, tracking a cursor.
type Reader struct {
	buf []byte
	pos int
}

// NewReader wraps buf.
func NewReader(buf []byte) *Reader { return &Reader{buf: buf} }

// Pos returns the current cursor offset.
func (r *Reader) Pos() int { return r.pos }

// Seek sets the cursor; off must be within [0, len(buf)].
func (r *Reader) Seek(off int) error {
	if off < 0 || off > len(r.buf) {
		return fmt.Errorf("nwio: seek %d out of range [0,%d]", off, len(r.buf))
	}
	r.pos = off
	return nil
}

// Remaining returns the number of unread bytes.
func (r *Reader) Remaining() int { return len(r.buf) - r.pos }

// Bytes returns the unread portion without copying.
func (r *Reader) Bytes() []byte { return r.buf[r.pos:] }

// U8 reads one byte.
func (r *Reader) U8() (uint8, error) {
	if r.Remaining() < 1 {
		return 0, ErrShort
	}
	v := r.buf[r.pos]
	r.pos++
	return v, nil
}

// U16 reads a little-endian uint16.
func (r *Reader) U16() (uint16, error) {
	if r.Remaining() < 2 {
		return 0, ErrShort
	}
	v := binary.LittleEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, nil
}

// U32 reads a little-endian uint32.
func (r *Reader) U32() (uint32, error) {
	if r.Remaining() < 4 {
		return 0, ErrShort
	}
	v := binary.LittleEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

// U64 reads a little-endian uint64.
func (r *Reader) U64() (uint64, error) {
	if r.Remaining() < 8 {
		return 0, ErrShort
	}
	v := binary.LittleEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, nil
}

// Raw returns n bytes without copying and advances the cursor.
func (r *Reader) Raw(n int) ([]byte, error) {
	if n < 0 || r.Remaining() < n {
		return nil, ErrShort
	}
	b := r.buf[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}
