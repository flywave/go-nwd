// Package nwd opens Autodesk Navisworks .nwd files (container format v8)
// and extracts identification metadata: signature mode, container version,
// the logical stream table of contents, and per-stream payload access.
//
// The parser is a pure-Go reconstruction of the ODA BimNv reader
// (TNW_Db.tx / OdNwStreamSplitter); see analysis/01-container.md and
// analysis/02-compress-chunk.md for the evidence trail.
package nwd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/flywave/go-nwd/internal/nwstream"
)

// Kind classifies the container signature mode.
type Kind uint8

const (
	// KindUnknown means the buffer is not a recognized NWD container.
	KindUnknown Kind = iota
	KindASCIILichunk
	KindBinaryLichunk
	KindBinaryNavisworks
)

func (k Kind) String() string {
	switch k {
	case KindASCIILichunk:
		return "nwd-ascii"
	case KindBinaryLichunk:
		return "nwd-binary-lichunk"
	case KindBinaryNavisworks:
		return "nwd-binary-navisworks"
	default:
		return "unknown"
	}
}

// MarshalJSON encodes Kind as its string form.
func (k Kind) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// StreamInfo describes one logical stream from the TOC.
// Offset/Size are absolute file coordinates; Prefix/Suffix are the leading/
// trailing splits applied before the middle payload (findings N15).
type StreamInfo struct {
	Name       string `json:"name"`
	Offset     int64  `json:"offset"`
	Size       int64  `json:"size"`
	Prefix     int32  `json:"prefix"`
	Suffix     int32  `json:"suffix"`
	Bitflag    uint32 `json:"bitflag"`
	Compressed bool   `json:"compressed"`
}

// Metadata is the M1/M2 identification result for one .nwd file.
type Metadata struct {
	Kind      Kind   `json:"kind"`
	FileSize  int64  `json:"file_size"`
	Version   int    `json:"container_version"`
	Precision string `json:"precision"`
	Build     string `json:"build"`

	TrailingBlockSize int64 `json:"trailing_block_size"`
	TrailingOffset    int64 `json:"trailing_offset"`
	MainPayloadSize   int   `json:"main_payload_size"`

	Streams []StreamInfo `json:"streams"`
}

// File is an opened NWD image with payload access.
type File struct {
	Metadata *Metadata
	c        *nwstream.Container
}

// Detect reports whether buf looks like an NWD container and returns the
// detected kind. It never returns an error for ordinary non-NWD data.
func Detect(buf []byte) Kind {
	cfg, ok := nwstream.DetectHeader(buf)
	if !ok {
		return KindUnknown
	}
	switch cfg.Mode {
	case nwstream.ModeASCIILichunk:
		return KindASCIILichunk
	case nwstream.ModeBinaryLichunk:
		return KindBinaryLichunk
	case nwstream.ModeBinaryNavisworks:
		return KindBinaryNavisworks
	default:
		return KindUnknown
	}
}

// Parse decodes an in-memory NWD image and returns identification metadata.
func Parse(buf []byte) (*Metadata, error) {
	f, err := Open(buf)
	if err != nil {
		return nil, err
	}
	return f.Metadata, nil
}

// Open decodes an in-memory NWD image, retaining payload access.
func Open(buf []byte) (*File, error) {
	c, err := nwstream.Parse(buf)
	if err != nil {
		return nil, err
	}
	md := &Metadata{
		Kind:              kindOf(c.Config.Mode),
		FileSize:          c.FileSize,
		Version:           c.Config.Version,
		Precision:         precisionString(c.Config.Precision),
		Build:             buildString(c.Config.Build),
		TrailingBlockSize: c.TrailingBlockSize,
		TrailingOffset:    c.TrailingOffset,
		MainPayloadSize:   len(c.MainPayload),
		Streams:           make([]StreamInfo, 0, len(c.Streams)),
	}
	for _, s := range c.Streams {
		md.Streams = append(md.Streams, StreamInfo{
			Name:       s.Name,
			Offset:     s.Offset,
			Size:       s.Size,
			Prefix:     s.Prefix,
			Suffix:     s.Suffix,
			Bitflag:    s.Bitfield,
			Compressed: s.Compressed(),
		})
	}
	return &File{Metadata: md, c: c}, nil
}

// StreamData returns the logical bytes of stream i: zlib-decompressed for
// compressed streams, raw middle payload otherwise.
func (f *File) StreamData(i int) ([]byte, error) {
	return f.c.StreamData(i)
}

// StreamByName returns the index of the named logical stream, or -1.
// Names may carry a directory prefix (e.g. "cache\\LcOpNwdPartition"); a
// bare name matches either the exact stored name or a "\\"-suffixed tail.
func (f *File) StreamByName(name string) int {
	for i, s := range f.Metadata.Streams {
		if s.Name == name || strings.HasSuffix(s.Name, "\\"+name) || strings.HasSuffix(s.Name, "/"+name) {
			return i
		}
	}
	return -1
}

// DecodeTree decodes the logical bytes of stream i as a partition tree
// (M3). The stream must begin with a PartitionNode envelope (type 32).
func (f *File) DecodeTree(i int) (*Tree, error) {
	data, err := f.c.StreamData(i)
	if err != nil {
		return nil, err
	}
	return DecodeTree(data)
}

// DecodeGeometryBlocks decrypts and parses the GeometryCompress stream i
// into its block table (M4, findings N23).
func (f *File) DecodeGeometryBlocks(i int) ([]GeometryBlock, error) {
	data, err := f.c.StreamData(i)
	if err != nil {
		return nil, err
	}
	return DecodeGeometryBlocks(data)
}

// DecodeSchemas decodes stream i as the CommonSchemas CDA definitions
// (M5, findings N27).
func (f *File) DecodeSchemas(i int) ([]Schema, error) {
	data, err := f.c.StreamData(i)
	if err != nil {
		return nil, err
	}
	return DecodeSchemas(data)
}

// DecodeObjectStream decodes stream i as a tolerant object graph
// (real-file path, findings N56).
func (f *File) DecodeObjectStream(i int, formatVersion uint32, limit int) (*ObjectStream, error) {
	data, err := f.c.StreamData(i)
	if err != nil {
		return nil, err
	}
	return DecodeObjectStream(data, formatVersion, limit), nil
}

// DecodePartitionRoot decodes partition stream i's root PartitionNode
// header (M3 real-file path, findings N42).
func (f *File) DecodePartitionRoot(i int) (*PartitionRoot, error) {
	data, err := f.c.StreamData(i)
	if err != nil {
		return nil, err
	}
	return DecodePartitionRoot(data)
}

// ScanStreamNames inflates stream i and extracts every Name object
// (property keys / class names) via the self-describing envelope markers
// (findings N44). Diagnostic extraction; see ScanNames for limitations.
func (f *File) ScanStreamNames(i int, limit int) ([]NameRecord, error) {
	data, err := f.c.StreamData(i)
	if err != nil {
		return nil, err
	}
	return ScanNames(data, limit), nil
}

// DecodeGeometryVertices extracts the real vertex geometry from the
// Geometry logical stream (M4 real-file path, findings N47/N48).
func (f *File) DecodeGeometryVertices(i int, limit int) ([]VertexBlock, error) {
	data, err := f.c.StreamData(i)
	if err != nil {
		return nil, err
	}
	return DecodeGeometryVertices(data, limit)
}

// OpenFile reads path and returns its metadata.
func OpenFile(path string) (*Metadata, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("nwd: %w", err)
	}
	md, err := Parse(buf)
	if err != nil {
		return nil, fmt.Errorf("nwd: %s: %w", path, err)
	}
	return md, nil
}

func kindOf(m nwstream.Mode) Kind {
	switch m {
	case nwstream.ModeASCIILichunk:
		return KindASCIILichunk
	case nwstream.ModeBinaryLichunk:
		return KindBinaryLichunk
	case nwstream.ModeBinaryNavisworks:
		return KindBinaryNavisworks
	default:
		return KindUnknown
	}
}

func precisionString(p nwstream.Precision) string {
	if p == nwstream.PrecisionSingle {
		return "single"
	}
	return "double"
}

func buildString(b nwstream.Build) string {
	if b == nwstream.BuildDebug {
		return "debug"
	}
	return "release"
}
