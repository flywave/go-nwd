package nwstream

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
)

// BuildSyntheticV8 assembles a minimal in-memory container v8 image.
// It is a test fixture generator based on analysis/01-container.md and the
// M2 findings (N14–N16); field choices follow the observed reader and will
// be revised when real samples arrive (U1–U4, U6).
//
// Each entry's Name/Bitfield/Offset/Size/Prefix/Suffix are filled by the
// builder: Offset/Size are computed from the layout, and Middle is placed at
// Offset+Prefix with optional zlib compression when Compressed is set.
type SynthStream struct {
	Name       string
	Bitfield   uint32 // low byte: compressed flag
	Prefix     []byte // leading raw chunk (copied at Offset)
	Middle     []byte // payload placed at Offset+len(Prefix)
	Compressed bool   // zlib-compress Middle and set bitfield low byte
	Suffix     []byte // trailing raw bytes after Middle
}

// BuildSyntheticV8 assembles a complete v8 image from logical streams.
func BuildSyntheticV8(streams []SynthStream, payloadGap []byte) []byte {
	// Header: 48-byte signature + version digits + NUL pad to 52.
	var header [HeaderSize]byte
	copy(header[:], SigASCIILichunk)
	header[SigCmpLen] = '8' // container version 8

	// Lay out stream regions sequentially right after the header.
	type placed struct {
		SynthStream
		Offset int64
		Size   int64
		MidOff int64 // absolute offset of (possibly compressed) middle
	}
	cursor := int64(HeaderSize)
	placedStreams := make([]placed, 0, len(streams))
	var body bytes.Buffer
	for _, s := range streams {
		off := cursor
		body.Write(s.Prefix)
		cursor += int64(len(s.Prefix))
		mid := s.Middle
		if s.Compressed {
			var zbuf bytes.Buffer
			zw := zlib.NewWriter(&zbuf)
			_, _ = zw.Write(s.Middle)
			_ = zw.Close()
			mid = zbuf.Bytes()
		}
		midOff := cursor
		body.Write(mid)
		cursor += int64(len(mid))
		body.Write(s.Suffix)
		cursor += int64(len(s.Suffix))
		placedStreams = append(placedStreams, placed{
			SynthStream: s,
			Offset:      off,
			Size:        cursor - off,
			MidOff:      midOff,
		})
	}
	// Optional filler between streams and trailing block.
	body.Write(payloadGap)

	// TOC body (findings N14/N15/N36): no stored name Adler-32.
	var toc bytes.Buffer
	_ = binary.Write(&toc, binary.LittleEndian, uint32(0xFFFFFFFF)) // -1
	_ = binary.Write(&toc, binary.LittleEndian, uint32(len(placedStreams)))
	for _, s := range placedStreams {
		name := []byte(s.Name)
		_ = binary.Write(&toc, binary.LittleEndian, uint32(len(name)))
		toc.Write(name)

		bf := s.Bitfield
		if s.Compressed {
			bf |= 0x1
		}
		var bfBuf [4]byte
		binary.LittleEndian.PutUint32(bfBuf[:], bf)
		toc.Write(bfBuf[:])

		if pad := (-toc.Len()) & 7; pad != 0 {
			toc.Write(make([]byte, pad))
		}
		var f8 [8]byte
		binary.LittleEndian.PutUint64(f8[:], uint64(s.Offset))
		toc.Write(f8[:])
		binary.LittleEndian.PutUint64(f8[:], uint64(s.Size))
		toc.Write(f8[:])
		var f4 [4]byte
		binary.LittleEndian.PutUint32(f4[:], uint32(int32(len(s.Prefix))))
		toc.Write(f4[:])
		binary.LittleEndian.PutUint32(f4[:], uint32(int32(len(s.Suffix))))
		toc.Write(f4[:])
	}

	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	_, _ = zw.Write(toc.Bytes())
	_ = zw.Close()

	// Trailing block: signature line + newline + 8-byte alignment + zlib + checksum.
	line := append([]byte(SigASCIILichunk), '\n')
	if pad := (-len(line)) & (alignTo - 1); pad != 0 {
		line = append(line, make([]byte, pad)...)
	}
	trailer := append(line, zbuf.Bytes()...)

	// Assemble (corrected real-file layout): header | stream body | trailer
	// | 8B gap | Int64 N (trailer offset) | 52B footer signature copy.
	var head bytes.Buffer
	head.Write(header[:])
	head.Write(body.Bytes())
	trailerOffset := int64(head.Len())

	var out bytes.Buffer
	out.Write(head.Bytes())
	out.Write(trailer)
	out.Write(make([]byte, trailerSlack))
	var nbuf [8]byte
	binary.LittleEndian.PutUint64(nbuf[:], uint64(trailerOffset))
	out.Write(nbuf[:])
	out.Write(header[:]) // footer signature copy
	return out.Bytes()
}
