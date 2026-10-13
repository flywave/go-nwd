package nwd

import "fmt"

// DecodeIndexTable decodes the geometry index table
// (OdNwGraphicVertexSetReader::readIndexTable@0xc275de, findings N53/N71).
//
// It reconstructs `count` uint32 indices from a byte stream using 2-bit tags
// (b & 0xC0) with the following encodings, where v == len(out) and `i` is the
// running emitted value:
//
//	0x00  run:   emit (b&0x3F)+1 consecutive values starting at v
//	0x40  back:  append out[len-v]      with v = b&0x3F
//	0x80  rep:   append the last value (b&0x3F)+1 times
//	0xD0  lit4:  append ~(b&0x0F)
//	0xE0  back12: append out[len - ((b&0x0F)<<8 | next)]
//	0xF0  lit16: append (next<<8 | next2)
//	0xF1  lit32: append 4 bytes big-endian
//
// The caller must align the stream after the table (alignPointer<0>).
// Returns the indices and the offset just past the consumed bytes.
func DecodeIndexTable(data []byte, pos, count int) ([]uint32, int, error) {
	if count < 0 {
		return nil, pos, fmt.Errorf("nwd: negative index count %d", count)
	}
	out := make([]uint32, 0, count)
	rd := func() (byte, error) {
		if pos >= len(data) {
			return 0, fmt.Errorf("nwd: index table truncated at %d", pos)
		}
		b := data[pos]
		pos++
		return b, nil
	}
	for len(out) < count {
		b, err := rd()
		if err != nil {
			return nil, pos, err
		}
		switch b & 0xC0 {
		case 0x00:
			n := int(b&0x3F) + 1
			for k := 0; k < n; k++ {
				out = append(out, uint32(len(out)))
			}
		case 0x40:
			n := int(b & 0x3F)
			idx := len(out) - n
			if idx < 0 || idx >= len(out) {
				return nil, pos, fmt.Errorf("nwd: bad backref %d at %d", n, pos)
			}
			out = append(out, out[idx])
		case 0x80:
			n := int(b&0x3F) + 1
			if len(out) == 0 {
				return nil, pos, fmt.Errorf("nwd: repeat with empty table at %d", pos)
			}
			v := out[len(out)-1]
			for k := 0; k < n; k++ {
				out = append(out, v)
			}
		case 0xC0:
			switch b & 0xF0 {
			case 0xD0:
				out = append(out, ^uint32(b&0x0F))
			case 0xE0:
				nb, err := rd()
				if err != nil {
					return nil, pos, err
				}
				off := int(b&0x0F)<<8 | int(nb)
				idx := len(out) - off
				if idx < 0 || idx >= len(out) {
					return nil, pos, fmt.Errorf("nwd: bad backref12 %d at %d", off, pos)
				}
				out = append(out, out[idx])
			default: // 0xF0 / 0xF1 (and undefined tags)
				switch b {
				case 0xF0:
					b1, err := rd()
					if err != nil {
						return nil, pos, err
					}
					b2, err := rd()
					if err != nil {
						return nil, pos, err
					}
					out = append(out, uint32(b1)<<8|uint32(b2))
				case 0xF1:
					var v uint32
					for k := 0; k < 4; k++ {
						bk, err := rd()
						if err != nil {
							return nil, pos, err
						}
						v = v<<8 | uint32(bk)
					}
					out = append(out, v)
				default:
					// Undefined tag: end of table.
					return out, pos, nil
				}
			}
		}
	}
	return out, pos, nil
}
