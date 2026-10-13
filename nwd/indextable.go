package nwd

import "fmt"

// DecodeIndexTable decodes the quantized geometry index table
// (OdNwGraphicVertexSetReader::readIndexTable@0xc275de, findings N53).
//
// It is a 2-bit-tag variable-length byte codec that reconstructs `count`
// uint32 indices. Tags (byte & 0xC0):
//
//	0x00  run: v = (b&0x3F)+1 sequential values from the running counter
//	0x40  backref: copy the value at position (len-v)
//	0x80  repeat: emit the last value v = (b&0x3F)+1 times
//	0xD0  literal (b&0x0F)
//	0xE0  12-bit literal ((b&0x0F)<<8 | next)
//	0xF0  28-bit literal ((b&0x0F)<<24 | 3 bytes)
//
// Returns the indices and the offset just past the consumed bytes.
func DecodeIndexTable(data []byte, pos, count int) ([]uint32, int, error) {
	if count < 0 {
		return nil, pos, fmt.Errorf("nwd: negative index count %d", count)
	}
	out := make([]uint32, 0, count)
	last := uint32(0)
	for len(out) < count {
		if pos >= len(data) {
			return nil, pos, fmt.Errorf("nwd: index table truncated at %d (%d/%d)", pos, len(out), count)
		}
		b := data[pos]
		pos++
		switch b & 0xC0 {
		case 0x00:
			v := int(b&0x3F) + 1
			for i := 0; i < v; i++ {
				out = append(out, last)
				last++
			}
		case 0x40:
			v := int(b & 0x3F)
			i := len(out) - v
			if i < 0 {
				return nil, pos, fmt.Errorf("nwd: bad backref at %d", pos)
			}
			out = append(out, out[i])
		case 0x80:
			v := int(b&0x3F) + 1
			if len(out) == 0 {
				return nil, pos, fmt.Errorf("nwd: repeat with empty table at %d", pos)
			}
			lit := out[len(out)-1]
			for i := 0; i < v; i++ {
				out = append(out, lit)
			}
		case 0xC0:
			switch b & 0xF0 {
			case 0xD0:
				out = append(out, uint32(b&0x0F))
			case 0xE0:
				if pos >= len(data) {
					return nil, pos, fmt.Errorf("nwd: 12-bit literal truncated")
				}
				out = append(out, uint32(b&0x0F)<<8|uint32(data[pos]))
				pos++
			case 0xF0:
				if pos+3 > len(data) {
					return nil, pos, fmt.Errorf("nwd: 28-bit literal truncated")
				}
				out = append(out, uint32(b&0x0F)<<24|uint32(data[pos])<<16|uint32(data[pos+1])<<8|uint32(data[pos+2]))
				pos += 3
			default: // 0xC0
				return nil, pos, fmt.Errorf("nwd: unhandled index tag %#x at %d", b, pos-1)
			}
		}
	}
	return out, pos, nil
}
