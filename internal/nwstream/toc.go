package nwstream

import (
	"encoding/binary"
	"fmt"
)

// tocMagic is the extended-TOC marker: the first rdInt32 must be -1
// (Load@0xbd3afd).
const tocMagic int32 = -1

// parseTOC decodes the inflated TOC. Layout verified against a real NWD
// (BCCCH coordination model, findings N36):
//
//	rdInt32  == -1                 (extended marker)
//	rdInt32  count
//	count × stream record:
//	  u32 nameLen; nameLen × u8 (UTF-8, may carry a "cache\" directory prefix)
//	  u32 bitfield                 (flags; low bits observed 0x1/0x100/0x10000/0x1000000)
//	  align to 8                   (alignPointer<1>)
//	  i64 offset                   (absolute file offset of the stream region)
//	  i64 size                     (region length)
//	  i32 prefix                   (leading raw split; 0 or 4 observed)
//	  i32 suffix                   (trailing trim)
//
// Confirmed: there is no stored per-record name Adler-32 and no trailing
// Blowfish TOC checksum (the M2 hypothesis was over-fit; see findings N35).
func parseTOC(b []byte) ([]StreamEntry, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("toc too short (%d)", len(b))
	}
	magic := int32(binary.LittleEndian.Uint32(b[0:4]))
	if magic != tocMagic {
		return nil, fmt.Errorf("toc magic %#x != -1 (extended marker)", uint32(magic))
	}
	count := int(binary.LittleEndian.Uint32(b[4:8]))
	if count > 1<<20 {
		return nil, fmt.Errorf("toc stream count %d exceeds limit", count)
	}

	pos := 8
	entries := make([]StreamEntry, 0, count)
	for idx := 0; idx < count; idx++ {
		var e StreamEntry
		if pos+4 > len(b) {
			return nil, fmt.Errorf("stream[%d] name length truncated", idx)
		}
		nameLen := binary.LittleEndian.Uint32(b[pos:])
		pos += 4
		if nameLen > 4096 || pos+int(nameLen) > len(b) {
			return nil, fmt.Errorf("stream[%d] name length %d invalid", idx, nameLen)
		}
		e.Name = string(b[pos : pos+int(nameLen)])
		pos += int(nameLen)

		if pos+4 > len(b) {
			return nil, fmt.Errorf("stream[%d] bitfield truncated", idx)
		}
		e.Bitfield = binary.LittleEndian.Uint32(b[pos:])
		pos += 4

		// alignPointer<1> → 8-byte alignment (bd51c0: andl $7).
		if pad := (-pos) & 7; pad != 0 {
			pos += pad
		}
		if pos+8+8+4+4 > len(b) {
			return nil, fmt.Errorf("stream[%d] fields truncated", idx)
		}
		e.Offset = int64(binary.LittleEndian.Uint64(b[pos:]))
		pos += 8
		e.Size = int64(binary.LittleEndian.Uint64(b[pos:]))
		pos += 8
		e.Prefix = int32(binary.LittleEndian.Uint32(b[pos:]))
		pos += 4
		e.Suffix = int32(binary.LittleEndian.Uint32(b[pos:]))
		pos += 4

		entries = append(entries, e)
	}
	return entries, nil
}
