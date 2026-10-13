package nwd

import (
	"encoding/binary"
	"fmt"
)

// This file implements the geometry element face-connectivity codecs that were
// reversed from TNW_Db.tx (findings N73/N74/N75):
//
//	OdNwGraphicTriangleSetElementReader::readElement@0xc2c1ea
//	OdNwGraphicLineSetElementReader::readVertexesPerLine@0xc2ecd4
//	OdNwGraphicTriangleSetElementReader::readIndexesPerLine@0xc2c918
//	OdNwGraphicVertexSetReader::readBits@0xc2737a
//
// An element serializes its sub-objects (VertexSet, TexCoordSet, NormalSet,
// ColorSet), then vertexesPerLine (vertices per face) and indexesPerLine (the
// flat vertex-index list). Faces are reconstructed by splitting indexesPerLine
// by vertexesPerLine.

// AlignUp returns pos advanced to the next multiple of n (n>0).
func AlignUp(pos, n int) int {
	if n <= 1 {
		return pos
	}
	if r := pos % n; r != 0 {
		return pos + (n - r)
	}
	return pos
}

// ReadBits decodes the bit-packed integer array produced by
// OdNwGraphicVertexSetReader::readBits@0xc2737a.
//
// The stream holds ceil(sum(flags)*count/32) little-endian uint32 words. Each
// word contributes 32 bits, most-significant bit first. The bit stream is then
// consumed row by row (count rows); within a row each component c with
// flags[c] > 0 reads flags[c] bits. The result is padded with zeros to stride.
func ReadBits(data []byte, pos int, flags []byte, count, stride int) ([]uint32, int, error) {
	sum := 0
	for _, f := range flags {
		sum += int(f)
	}
	totalBits := sum * count
	words := (totalBits + 31) / 32
	raw := make([]uint32, 0, words*32)
	for k := 0; k < words; k++ {
		if pos+4 > len(data) {
			return nil, pos, fmt.Errorf("nwd: readBits truncated at %d", pos)
		}
		v := binary.LittleEndian.Uint32(data[pos:])
		pos += 4
		for b := 31; b >= 0; b-- {
			raw = append(raw, (v>>uint(b))&1)
		}
	}
	out := make([]uint32, 0, count)
	o := 0
	for j := 0; j < count; j++ {
		for c := 0; c < len(flags); c++ {
			if flags[c] == 0 {
				continue
			}
			var val uint32
			for t := 0; t < int(flags[c]); t++ {
				if o >= len(raw) {
					return nil, pos, fmt.Errorf("nwd: readBits bitstream underrun")
				}
				val = val<<1 | raw[o]
				o++
			}
			out = append(out, val)
		}
	}
	for len(out) < stride {
		out = append(out, 0)
	}
	return out, pos, nil
}

// ReadVertexesPerLine decodes the per-face vertex counts
// (readVertexesPerLine@0xc2ecd4).
//
// Uncompressed (lengthsCompressed == false):
//
//	[u32 n] then n values (u16 when wide==true, else the low 16 bits of a u32)
//
// Compressed (lengthsCompressed == true):
//
//	[u32 total][align] [i32 bitsPerValue][i32 uniqueCount]
//	[bit-packed unique values][optional index table when uniqueCount < total]
//
// wide corresponds to formatVersion > 0x4a (74). align is the stream alignment
// (OdNmStreamAlignment 0; empirically 4 or 8).
func ReadVertexesPerLine(data []byte, pos int, lengthsCompressed, wide bool, align int) ([]uint16, int, error) {
	if !lengthsCompressed {
		if pos+4 > len(data) {
			return nil, pos, fmt.Errorf("nwd: vpl truncated")
		}
		n := int(int32(binary.LittleEndian.Uint32(data[pos:])))
		pos += 4
		if n < 0 || n > 50_000_000 {
			return nil, pos, fmt.Errorf("nwd: vpl bad count %d", n)
		}
		out := make([]uint16, 0, n)
		if wide {
			for i := 0; i < n; i++ {
				if pos+2 > len(data) {
					return nil, pos, fmt.Errorf("nwd: vpl truncated")
				}
				out = append(out, binary.LittleEndian.Uint16(data[pos:]))
				pos += 2
			}
			pos = AlignUp(pos, align)
		} else {
			for i := 0; i < n; i++ {
				if pos+4 > len(data) {
					return nil, pos, fmt.Errorf("nwd: vpl truncated")
				}
				out = append(out, uint16(binary.LittleEndian.Uint32(data[pos:])))
				pos += 4
			}
		}
		return out, pos, nil
	}
	if pos+4 > len(data) {
		return nil, pos, fmt.Errorf("nwd: vpl truncated")
	}
	total := int(int32(binary.LittleEndian.Uint32(data[pos:])))
	pos = AlignUp(pos+4, align)
	if pos+8 > len(data) {
		return nil, pos, fmt.Errorf("nwd: vpl truncated")
	}
	bits := int(int32(binary.LittleEndian.Uint32(data[pos:])))
	unique := int(int32(binary.LittleEndian.Uint32(data[pos+4:])))
	pos += 8
	if bits < 0 || bits > 32 || unique < 0 {
		return nil, pos, fmt.Errorf("nwd: vpl bad bits/unique %d/%d", bits, unique)
	}
	vals, np, err := ReadBits(data, pos, []byte{byte(bits), 0, 0, 0}, unique, unique)
	if err != nil {
		return nil, pos, err
	}
	pos = np
	tbl := make([]uint32, 0, total)
	if unique < total {
		t, np2, err := DecodeIndexTable(data, pos, total)
		if err != nil {
			return nil, pos, err
		}
		tbl, pos = t, np2
	} else {
		for i := 0; i < total; i++ {
			tbl = append(tbl, uint32(i))
		}
	}
	out := make([]uint16, 0, total)
	for i := 0; i < total; i++ {
		if int(tbl[i]) < len(vals) {
			out = append(out, uint16(vals[tbl[i]]))
		}
	}
	return out, pos, nil
}

// ReadIndexesPerLine decodes the flat vertex-index list
// (readIndexesPerLine@0xc2c918).
//
// Uncompressed (indicesCompressed == false):
//
//	[i32 n] then n values (u16 when wide==true, else the low 16 bits of a u32)
//
// Compressed (indicesCompressed == true):
//
//	[i32 n][index table of n entries]
//
// wide corresponds to formatVersion > 0x4a (74).
func ReadIndexesPerLine(data []byte, pos int, indicesCompressed, wide bool, align int) ([]uint16, int, error) {
	if pos+4 > len(data) {
		return nil, pos, fmt.Errorf("nwd: ipl truncated")
	}
	n := int(int32(binary.LittleEndian.Uint32(data[pos:])))
	pos += 4
	if !indicesCompressed {
		if n < 0 || n > 50_000_000 {
			return nil, pos, fmt.Errorf("nwd: ipl bad count %d", n)
		}
		out := make([]uint16, 0, n)
		if wide {
			for i := 0; i < n; i++ {
				if pos+2 > len(data) {
					return nil, pos, fmt.Errorf("nwd: ipl truncated")
				}
				out = append(out, binary.LittleEndian.Uint16(data[pos:]))
				pos += 2
			}
			pos = AlignUp(pos, align)
		} else {
			for i := 0; i < n; i++ {
				if pos+4 > len(data) {
					return nil, pos, fmt.Errorf("nwd: ipl truncated")
				}
				out = append(out, uint16(binary.LittleEndian.Uint32(data[pos:])))
				pos += 4
			}
		}
		return out, pos, nil
	}
	if n <= 0 {
		return nil, pos, nil
	}
	tbl, np, err := DecodeIndexTable(data, pos, n)
	if err != nil {
		return nil, pos, err
	}
	out := make([]uint16, 0, len(tbl))
	for _, v := range tbl {
		out = append(out, uint16(v))
	}
	return out, np, nil
}

// SplitFaces groups a flat index list into faces using the per-face vertex
// counts from vertexesPerLine. A negative count (int16) introduces a triangle
// fan/loop; its absolute value is used as the group size.
func SplitFaces(indexes []uint16, perLine []uint16) [][]uint16 {
	faces := make([][]uint16, 0, len(perLine))
	i := 0
	for _, c := range perLine {
		n := int(int16(c))
		if n < 0 {
			n = -n
		}
		if n <= 0 || i+n > len(indexes) {
			break
		}
		face := make([]uint16, n)
		copy(face, indexes[i:i+n])
		i += n
		faces = append(faces, face)
	}
	return faces
}
