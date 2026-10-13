package nwstream

import (
	"encoding/binary"
	"fmt"

	"github.com/flywave/go-nwd/internal/blowfish"
)

// adler32Update is the incremental Adler-32 step (mod 65521), matching
// NwAdler32's rolling usage in the TOC loop (Load@0xbd3bf0).
func adler32Update(acc uint32, p []byte) uint32 {
	const mod = 65521
	s1 := acc & 0xffff
	s2 := (acc >> 16) & 0xffff
	for _, c := range p {
		s1 += uint32(c)
		s2 += s1
	}
	s1 %= mod
	s2 %= mod
	return s2<<16 | s1
}

// sBlowfishKey is the fixed 32-byte Blowfish key used to protect the TOC
// rolling Adler-32 (E2: sBlowfishKey@0x16ecfa0, GenSubkeys len=0x20).
var sBlowfishKey = []byte{
	0xf1, 0xfb, 0xf2, 0x39, 0xdb, 0xb7, 0x88, 0x49,
	0x7a, 0xe7, 0x45, 0x9f, 0xa3, 0xf9, 0x0e, 0x8f,
	0xfa, 0x5a, 0xb9, 0x83, 0xac, 0xec, 0xbf, 0x66,
	0x49, 0x1d, 0xf2, 0x32, 0x83, 0x8d, 0x6e, 0x6b,
}

// tocMagic is the extended-TOC marker: the first rdInt32 must be -1
// (Load@0xbd3afd; non-(-1) takes the error path "Read extensions != -1 !").
const tocMagic int32 = -1

// parseTOC decodes the inflated TOC (findings N7/N14/N15):
//
//	rdInt32  == -1            (extended marker)
//	rdInt32  count
//	count × stream record:
//	  u32 nameLen; name bytes; u32 adler32(name)   [rolling]
//	  u32 bitfield                                  [low byte: compressed flag]
//	  align to 8
//	  i64 offset; i64 size; i32 prefix; i32 suffix
//
// The rolling Adler-32 continues over bitfield/offset/size/prefix/suffix and
// is compared against the Blowfish-encrypted trailer checksum by the caller.
func parseTOC(b []byte) ([]StreamEntry, uint32, error) {
	if len(b) < 8 {
		return nil, 0, fmt.Errorf("toc too short (%d)", len(b))
	}
	magic := int32(binary.LittleEndian.Uint32(b[0:4]))
	if magic != tocMagic {
		return nil, 0, fmt.Errorf("toc magic %#x != -1 (extended marker)", uint32(magic))
	}
	count := int(binary.LittleEndian.Uint32(b[4:8]))
	if count > 4096 {
		return nil, 0, fmt.Errorf("toc stream count %d exceeds limit", count)
	}

	pos := 8
	acc := uint32(1) // Adler-32 seed (Load@0xbd3a13: movl $1)
	entries := make([]StreamEntry, 0, count)
	for idx := 0; idx < count; idx++ {
		var e StreamEntry
		if pos+4 > len(b) {
			return nil, 0, fmt.Errorf("stream[%d] name length truncated", idx)
		}
		nameLen := binary.LittleEndian.Uint32(b[pos:])
		pos += 4
		if nameLen > 1024 || pos+int(nameLen) > len(b) {
			return nil, 0, fmt.Errorf("stream[%d] name length %d invalid", idx, nameLen)
		}
		name := b[pos : pos+int(nameLen)]
		pos += int(nameLen)
		e.Name = string(name)
		acc = adler32Update(acc, name)

		if pos+4 > len(b) {
			return nil, 0, fmt.Errorf("stream[%d] name adler truncated", idx)
		}
		e.NameAdler32 = binary.LittleEndian.Uint32(b[pos:])
		pos += 4

		if pos+4 > len(b) {
			return nil, 0, fmt.Errorf("stream[%d] bitfield truncated", idx)
		}
		e.Bitfield = binary.LittleEndian.Uint32(b[pos:])
		pos += 4
		acc = adler32Update(acc, b[pos-4:pos])

		// alignPointer<1> → 8-byte alignment (bd51c0: andl $7).
		if pad := (-pos) & 7; pad != 0 {
			pos += pad
		}
		if pos+8+8+4+4 > len(b) {
			return nil, 0, fmt.Errorf("stream[%d] fields truncated", idx)
		}
		e.Offset = int64(binary.LittleEndian.Uint64(b[pos:]))
		acc = adler32Update(acc, b[pos:pos+8])
		pos += 8
		e.Size = int64(binary.LittleEndian.Uint64(b[pos:]))
		acc = adler32Update(acc, b[pos:pos+8])
		pos += 8
		e.Prefix = int32(binary.LittleEndian.Uint32(b[pos:]))
		acc = adler32Update(acc, b[pos:pos+4])
		pos += 4
		e.Suffix = int32(binary.LittleEndian.Uint32(b[pos:]))
		acc = adler32Update(acc, b[pos:pos+4])
		pos += 4

		entries = append(entries, e)
	}
	return entries, acc, nil
}

// verifyTOCChecksum decrypts the 8-byte Blowfish trailer and checks it
// against the rolling Adler-32 (Load@0xbd3e89–0xbd3ef1): the decrypted
// u64 must be two identical copies of acc.
func verifyTOCChecksum(raw8 []byte, acc uint32) error {
	if len(raw8) != 8 {
		return fmt.Errorf("toc checksum length %d", len(raw8))
	}
	block, err := blowfish.NewCipher(sBlowfishKey)
	if err != nil {
		return fmt.Errorf("blowfish key: %w", err)
	}
	var plain [8]byte
	block.Decrypt(plain[:], raw8)
	lo := binary.LittleEndian.Uint32(plain[0:4])
	hi := binary.LittleEndian.Uint32(plain[4:8])
	if lo != hi {
		return fmt.Errorf("toc checksum halves differ (%#x != %#x)", lo, hi)
	}
	if lo != acc {
		return fmt.Errorf("toc checksum %#x != rolling adler %#x", lo, acc)
	}
	return nil
}

// encryptTOCChecksum is the inverse of verifyTOCChecksum, used by the
// synthetic fixture builder.
func encryptTOCChecksum(acc uint32) []byte {
	block, err := blowfish.NewCipher(sBlowfishKey)
	if err != nil {
		panic(err) // fixed key; cannot fail
	}
	var plain, cipher [8]byte
	binary.LittleEndian.PutUint32(plain[0:4], acc)
	binary.LittleEndian.PutUint32(plain[4:8], acc)
	block.Encrypt(cipher[:], plain[:])
	return cipher[:]
}
