package nwd

import (
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"math"

	"github.com/flywave/go-nwd/internal/blowfish"
)

// sGeometryCompressKey is the fixed 32-byte Blowfish key protecting the
// GeometryCompress stream (E2: sGeometryCompressKey@0x16ee400; same value
// as the M2 TOC key, findings N23).
var sGeometryCompressKey = []byte{
	0xf1, 0xfb, 0xf2, 0x39, 0xdb, 0xb7, 0x88, 0x49,
	0x7a, 0xe7, 0x45, 0x9f, 0xa3, 0xf9, 0x0e, 0x8f,
	0xfa, 0x5a, 0xb9, 0x83, 0xac, 0xec, 0xbf, 0x66,
	0x49, 0x1d, 0xf2, 0x32, 0x83, 0x8d, 0x6e, 0x6b,
}

// GeometryBlock is one decrypted geometry payload block.
type GeometryBlock struct {
	Data  []byte
	Adler uint32
}

// DecryptGeometryStream applies the 8-byte-block Blowfish-ECB transform
// used by OdNwGeometryCompressStreamLoader::parseStream@0xd3c2f1
// (findings N23). Input length must be a multiple of 8.
func DecryptGeometryStream(enc []byte) ([]byte, error) {
	if len(enc)%8 != 0 {
		return nil, fmt.Errorf("nwd: geometry stream length %d not a multiple of 8", len(enc))
	}
	block, err := blowfish.NewCipher(sGeometryCompressKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(enc))
	for i := 0; i < len(enc); i += 8 {
		block.Decrypt(out[i:i+8], enc[i:i+8])
	}
	return out, nil
}

// EncryptGeometryStream is the inverse, used by fixture builders.
func EncryptGeometryStream(plain []byte) ([]byte, error) {
	if len(plain)%8 != 0 {
		return nil, fmt.Errorf("nwd: geometry stream length %d not a multiple of 8", len(plain))
	}
	block, err := blowfish.NewCipher(sGeometryCompressKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	for i := 0; i < len(plain); i += 8 {
		block.Encrypt(out[i:i+8], plain[i:i+8])
	}
	return out, nil
}

// DecodeGeometryBlocks decrypts a GeometryCompress stream and parses its
// block table (findings N23, fixture-pinned until U13):
//
//	i32 blockCount
//	per block: i32 size, size bytes, u32 Adler-32
func DecodeGeometryBlocks(enc []byte) ([]GeometryBlock, error) {
	plain, err := DecryptGeometryStream(enc)
	if err != nil {
		return nil, err
	}
	r := newBR(plain)
	count, err := r.i32()
	if err != nil {
		return nil, fmt.Errorf("nwd: geometry block count: %w", err)
	}
	if count < 0 || count > 1<<20 {
		return nil, fmt.Errorf("nwd: geometry block count %d invalid", count)
	}
	blocks := make([]GeometryBlock, 0, count)
	for i := int32(0); i < count; i++ {
		sz, err := r.i32()
		if err != nil {
			return nil, fmt.Errorf("nwd: block[%d] size: %w", i, err)
		}
		if sz < 0 {
			return nil, fmt.Errorf("nwd: block[%d] negative size %d", i, sz)
		}
		data, err := r.raw(int(sz))
		if err != nil {
			return nil, fmt.Errorf("nwd: block[%d] data: %w", i, err)
		}
		ad, err := r.u32()
		if err != nil {
			return nil, fmt.Errorf("nwd: block[%d] adler: %w", i, err)
		}
		blocks = append(blocks, GeometryBlock{Data: data, Adler: ad})
	}
	return blocks, nil
}

// BuildGeometryBlocks is the fixture-side inverse of DecodeGeometryBlocks.
func BuildGeometryBlocks(blocks [][]byte) ([]byte, error) {
	var plain []byte
	plain = appendI32(plain, int32(len(blocks)))
	for _, b := range blocks {
		plain = appendI32(plain, int32(len(b)))
		plain = append(plain, b...)
		plain = appendU32(plain, adler32.Checksum(b))
	}
	// Pad to 8-byte boundary before encryption.
	if pad := len(plain) % 8; pad != 0 {
		plain = append(plain, make([]byte, 8-pad)...)
	}
	return EncryptGeometryStream(plain)
}

// DecodeVertexSet decodes the uncompressed GraphicVertexSet payload
// (findings N24): i32 count + count × (f32 x,y,z).
func DecodeVertexSet(data []byte) ([][3]float64, error) {
	r := newBR(data)
	count, err := r.i32()
	if err != nil {
		return nil, fmt.Errorf("nwd: vertex count: %w", err)
	}
	if count < 0 || count > 1<<27 {
		return nil, fmt.Errorf("nwd: vertex count %d invalid", count)
	}
	verts := make([][3]float64, 0, count)
	for i := int32(0); i < count; i++ {
		b, err := r.raw(12)
		if err != nil {
			return nil, fmt.Errorf("nwd: vertex[%d]: %w", i, err)
		}
		x := float64(f32(b[0:4]))
		y := float64(f32(b[4:8]))
		z := float64(f32(b[8:12]))
		verts = append(verts, [3]float64{x, y, z})
	}
	return verts, nil
}

// EncodeVertexSet is the fixture-side inverse of DecodeVertexSet.
func EncodeVertexSet(verts [][3]float64) []byte {
	out := appendI32(nil, int32(len(verts)))
	for _, v := range verts {
		var b [12]byte
		binary.LittleEndian.PutUint32(b[0:], f32bits(float32(v[0])))
		binary.LittleEndian.PutUint32(b[4:], f32bits(float32(v[1])))
		binary.LittleEndian.PutUint32(b[8:], f32bits(float32(v[2])))
		out = append(out, b[:]...)
	}
	return out
}

// DecodeIndexList decodes the uncompressed index payload:
// i32 count + count × u32.
func DecodeIndexList(data []byte) ([]uint32, error) {
	r := newBR(data)
	count, err := r.i32()
	if err != nil {
		return nil, fmt.Errorf("nwd: index count: %w", err)
	}
	if count < 0 || count > 1<<27 {
		return nil, fmt.Errorf("nwd: index count %d invalid", count)
	}
	idx := make([]uint32, 0, count)
	for i := int32(0); i < count; i++ {
		v, err := r.u32()
		if err != nil {
			return nil, fmt.Errorf("nwd: index[%d]: %w", i, err)
		}
		idx = append(idx, v)
	}
	return idx, nil
}

// EncodeIndexList is the fixture-side inverse of DecodeIndexList.
func EncodeIndexList(idx []uint32) []byte {
	out := appendI32(nil, int32(len(idx)))
	for _, v := range idx {
		out = appendU32(out, v)
	}
	return out
}

// Mesh is an assembled triangle mesh (uncompressed geometry path).
type Mesh struct {
	Vertices  [][3]float64 `json:"vertices"`
	Triangles []uint32     `json:"triangles"` // 3 indices per triangle
}

// BuildMesh assembles a mesh from a vertex set and a triangle index list.
// Triangles length must be a multiple of 3.
func BuildMesh(vertexSet, triangleIndices []byte) (*Mesh, error) {
	verts, err := DecodeVertexSet(vertexSet)
	if err != nil {
		return nil, err
	}
	tris, err := DecodeIndexList(triangleIndices)
	if err != nil {
		return nil, err
	}
	if len(tris)%3 != 0 {
		return nil, fmt.Errorf("nwd: triangle index count %d not a multiple of 3", len(tris))
	}
	for _, t := range tris {
		if int(t) >= len(verts) {
			return nil, fmt.Errorf("nwd: triangle index %d out of range (%d vertices)", t, len(verts))
		}
	}
	return &Mesh{Vertices: verts, Triangles: tris}, nil
}

func appendI32(b []byte, v int32) []byte {
	var x [4]byte
	binary.LittleEndian.PutUint32(x[:], uint32(v))
	return append(b, x[:]...)
}

func appendU32(b []byte, v uint32) []byte {
	var x [4]byte
	binary.LittleEndian.PutUint32(x[:], v)
	return append(b, x[:]...)
}

func f32(b []byte) float32     { return math.Float32frombits(binary.LittleEndian.Uint32(b)) }
func f32bits(v float32) uint32 { return math.Float32bits(v) }
