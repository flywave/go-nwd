package nwstream

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// Footer constants recovered from Load@0xbd34b4 (findings N5).
const (
	// footerAnchor is the seek offset from EOF where the trailing-block size
	// Int64 lives (fileSize-0x3c).
	footerAnchor = 0x3c

	// footerSize is the total footer span: 8-byte size + 52-byte header copy
	// (0x3c).
	footerSize = 0x3c

	// trailerSlack is the 8-byte gap between the trailing block and the
	// footer anchor (findings N5, semantics unknown U3).
	trailerSlack = 8

	// trailerTrail is the total tail after the trailing config block:
	// 8-byte gap + 8-byte offset Int64 + 52-byte footer signature (0x44).
	trailerTrail = 0x44

	// alignTo is the byte alignment applied after the trailing-block
	// signature line before the zlib stream (readStreamConfig@0xbd32b5:
	// pad = (-consumed) & 7).
	alignTo = 8
)

// StreamEntry is one logical stream record from the inflated TOC.
// Field semantics are pinned by parseStream@0xbd10dd (findings N15):
//
//	Offset  — absolute file offset of the stream region
//	Size    — total byte length of the region
//	Prefix  — leading raw bytes split off as the first chunk (>0); ==4 has
//	          special first-chunk handling (partial, findings U6)
//	Suffix  — trailing bytes excluded from the tail
//	Bitfield low byte != 0 — region is a single compressed blob
type StreamEntry struct {
	Name     string
	Bitfield uint32
	Offset   int64
	Size     int64
	Prefix   int32
	Suffix   int32

	// RawZlib is set during Parse when the region begins with a zlib
	// header (findings N36). It is authoritative over the bitfield.
	RawZlib bool
}

// Compressed reports whether the stream region is zlib-compressed.
func (e StreamEntry) Compressed() bool { return e.RawZlib }

// Container is the parsed v8 NWD container envelope.
type Container struct {
	Config Config

	// FileSize is the total input length.
	FileSize int64

	// TrailingBlockSize is the footer-anchored Int64 N (findings N5).
	TrailingBlockSize int64

	// TrailingOffset is the absolute offset of the trailing block (P).
	TrailingOffset int64

	// MainPayload is the byte range [HeaderSize, TrailingOffset).
	// Stream regions (TOC offsets) index the full file, not this slice.
	MainPayload []byte

	// data is the complete file image (retained for stream extraction).
	data []byte

	// Streams holds TOC entries in file order.
	Streams []StreamEntry
}

// Parse decodes a complete in-memory NWD image at container version 8.
// Versions 2–7 return ErrUnsupportedVersion; other failures are typed errors.
func Parse(data []byte) (*Container, error) {
	if len(data) < HeaderSize+footerSize {
		return nil, fmt.Errorf("nwstream: file too small (%d bytes)", len(data))
	}

	cfg, ok := DetectHeader(data[:HeaderSize])
	if !ok {
		return nil, ErrNotNWD
	}
	if cfg.Version < 2 || cfg.Version > 8 {
		return nil, fmt.Errorf("nwstream: %w: version %d", ErrUnsupportedVersion, cfg.Version)
	}
	if cfg.Version < 8 {
		return nil, fmt.Errorf("nwstream: %w: container v%d (LoadOld)", ErrUnsupportedVersion, cfg.Version)
	}

	fileSize := int64(len(data))

	// Footer Int64 at fileSize-0x3c is the absolute OFFSET of the trailing
	// configuration block (verified against a real NWD: it points at the
	// navisworks-variant signature line). The 52-byte footer signature copy
	// follows the Int64.
	footerOff := fileSize - footerAnchor
	n := int64le(data[footerOff : footerOff+8])
	if n < HeaderSize || n > fileSize-trailerTrail {
		return nil, fmt.Errorf("nwstream: trailing-block offset %d out of range", n)
	}
	hdrCopy := data[footerOff+8 : footerOff+8+HeaderSize]
	if !bytes.Equal(hdrCopy, data[:HeaderSize]) {
		return nil, ErrFooterMismatch
	}

	// Trailing config block spans [N, fileSize-0x44); after it come the
	// 8-byte gap, the Int64 N and the 52-byte footer signature.
	trailingEnd := fileSize - trailerTrail
	if n >= trailingEnd {
		return nil, fmt.Errorf("nwstream: empty trailing block (N=%d end=%d)", n, trailingEnd)
	}
	trailer := data[n:trailingEnd]
	p := n // main payload ends where the trailing block begins

	// Parse the trailing-block signature line, then align to 8 bytes from
	// the block start (readStreamConfig@0xbd32af..0xbd32ed).
	zlibOff, err := skipSignatureLine(trailer)
	if err != nil {
		return nil, fmt.Errorf("nwstream: trailing signature: %w", err)
	}

	// The zlib TOC starts after the signature line and runs to the end of
	// the trailing block (verified against a real NWD: the deflate stream
	// fills the remainder exactly; there is no trailing checksum). Go's
	// zlib reader stops at the stream's own end, ignoring any trailing bytes.
	body := trailer[zlibOff:]
	if len(body) < 4 {
		return nil, fmt.Errorf("nwstream: trailing body too short")
	}

	toc, err := inflateAll(body)
	if err != nil {
		return nil, fmt.Errorf("nwstream: toc inflate: %w", err)
	}
	streams, err := parseTOC(toc)
	if err != nil {
		return nil, fmt.Errorf("nwstream: toc: %w", err)
	}

	// Validate stream regions against the main payload [HeaderSize, N).
	for i := range streams {
		s := &streams[i]
		if s.Offset < HeaderSize || s.Size < 0 || s.Offset+s.Size > p {
			return nil, fmt.Errorf("nwstream: stream[%d] %q region [%d,%d) outside main payload (end=%d)",
				i, s.Name, s.Offset, s.Offset+s.Size, p)
		}
		if s.Prefix < 0 || s.Suffix < 0 || int64(s.Prefix)+int64(s.Suffix) > s.Size {
			return nil, fmt.Errorf("nwstream: stream[%d] %q prefix/suffix %d/%d invalid for size %d",
				i, s.Name, s.Prefix, s.Suffix, s.Size)
		}
		start := s.Offset + int64(s.Prefix)
		end := s.Offset + s.Size - int64(s.Suffix)
		s.RawZlib = end > start && zlibMagic(data[start:end])
	}

	c := &Container{
		Config:            cfg,
		FileSize:          fileSize,
		TrailingBlockSize: trailingEnd - n,
		TrailingOffset:    p,
		MainPayload:       data[HeaderSize:p],
		data:              data,
		Streams:           streams,
	}
	return c, nil
}

// StreamRegion returns the raw region bytes for stream i after applying
// the prefix/suffix split (parseStream@0xbd1326): [offset+prefix,
// offset+size-suffix).
func (c *Container) StreamRegion(i int) ([]byte, error) {
	if i < 0 || i >= len(c.Streams) {
		return nil, fmt.Errorf("nwstream: stream index %d out of range", i)
	}
	s := c.Streams[i]
	start := s.Offset + int64(s.Prefix)
	end := s.Offset + s.Size - int64(s.Suffix)
	if start < 0 || end > int64(len(c.data)) || start > end {
		return nil, fmt.Errorf("nwstream: stream %q region [%d,%d) invalid", s.Name, start, end)
	}
	return c.data[start:end], nil
}

// StreamPrefix returns the leading Prefix bytes split off as the first
// chunk (nil when Prefix == 0).
func (c *Container) StreamPrefix(i int) ([]byte, error) {
	if i < 0 || i >= len(c.Streams) {
		return nil, fmt.Errorf("nwstream: stream index %d out of range", i)
	}
	s := c.Streams[i]
	if s.Prefix == 0 {
		return nil, nil
	}
	start := s.Offset
	end := s.Offset + int64(s.Prefix)
	return c.data[start:end], nil
}

// zlibMagic reports whether b begins with a plausible zlib header (CMF
// 0x78, the common deflate window). Verified against a real NWD: every
// non-encrypted stream region starts with 0x78 0x9c (findings N36).
func zlibMagic(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	if b[0] != 0x78 {
		return false
	}
	// CMF/FLG checksum must be a multiple of 31 and FCHECK valid.
	return (uint16(b[0])<<8|uint16(b[1]))%31 == 0
}

// StreamData returns the logical stream bytes: zlib-decompressed when the
// region begins with a zlib header, raw otherwise (encrypted geometry
// containers keep their raw bytes for the geometry layer).
func (c *Container) StreamData(i int) ([]byte, error) {
	raw, err := c.StreamRegion(i)
	if err != nil {
		return nil, err
	}
	if zlibMagic(raw) {
		return Inflate(raw)
	}
	return raw, nil
}

// skipSignatureLine consumes whitespace-separated signature words from the
// start of the trailing block and returns the 8-byte-aligned offset where
// the zlib stream begins (findings N3 + readStreamConfig alignment).
func skipSignatureLine(block []byte) (int, error) {
	i := 0
	for i < len(block) && isSpace(block[i]) {
		i++
	}
	words := 0
	for i < len(block) {
		start := i
		for i < len(block) && !isSpace(block[i]) {
			i++
		}
		if i == start {
			break
		}
		words++
		if !isSignatureWord(string(block[start:i])) {
			i = start
			break
		}
		for i < len(block) && isSpace(block[i]) {
			i++
		}
	}
	if words == 0 {
		return 0, fmt.Errorf("no signature words")
	}
	if pad := (-i) & (alignTo - 1); pad != 0 {
		i += pad
	}
	if i > len(block) {
		return 0, fmt.Errorf("alignment past end of trailing block")
	}
	return i, nil
}

func isSignatureWord(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// Inflate decompresses a zlib blob (oda_z_inflate is standard zlib,
// findings N6).
func Inflate(comp []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(comp))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

func inflateAll(comp []byte) ([]byte, error) { return Inflate(comp) }

func int64le(b []byte) int64 {
	return int64(uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56)
}
