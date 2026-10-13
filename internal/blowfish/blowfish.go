package blowfish

import (
	"crypto/cipher"
	"encoding/binary"
	"strconv"
)

// BlockSize is the Blowfish block size in bytes.
const BlockSize = 8

// Cipher is a Blowfish cipher instance. It implements cipher.Block.
type Cipher struct {
	p      [18]uint32
	s0, s1 [256]uint32
	s2, s3 [256]uint32
}

// KeySizeError reports an invalid key length.
type KeySizeError int

func (k KeySizeError) Error() string {
	return "blowfish: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new Cipher. The key argument must be
// between 1 and 56 bytes long.
func NewCipher(key []byte) (*Cipher, error) {
	k := len(key)
	if k < 1 || k > 56 {
		return nil, KeySizeError(k)
	}
	c := new(Cipher)
	c.expandKey(key)
	return c, nil
}

// BlockSize implements cipher.Block.
func (c *Cipher) BlockSize() int { return BlockSize }

// Encrypt encrypts the 8-byte block src into dst. dst and src may overlap.
func (c *Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("blowfish: input not full block")
	}
	if len(dst) < BlockSize {
		panic("blowfish: output not full block")
	}
	xl := binary.BigEndian.Uint32(src[0:4])
	xr := binary.BigEndian.Uint32(src[4:8])
	xl, xr = c.encrypt(xl, xr)
	binary.BigEndian.PutUint32(dst[0:4], xl)
	binary.BigEndian.PutUint32(dst[4:8], xr)
}

// Decrypt decrypts the 8-byte block src into dst.
func (c *Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("blowfish: input not full block")
	}
	if len(dst) < BlockSize {
		panic("blowfish: output not full block")
	}
	xl := binary.BigEndian.Uint32(src[0:4])
	xr := binary.BigEndian.Uint32(src[4:8])
	xl, xr = c.decrypt(xl, xr)
	binary.BigEndian.PutUint32(dst[0:4], xl)
	binary.BigEndian.PutUint32(dst[4:8], xr)
}

func (c *Cipher) f(x uint32) uint32 {
	return ((c.s0[byte(x>>24)] + c.s1[byte(x>>16)]) ^ c.s2[byte(x>>8)]) + c.s3[byte(x)]
}

func (c *Cipher) encrypt(xl, xr uint32) (uint32, uint32) {
	for i := 0; i < 16; i += 2 {
		xl ^= c.p[i]
		xr ^= c.f(xl)
		xr ^= c.p[i+1]
		xl ^= c.f(xr)
	}
	xl ^= c.p[16]
	xr ^= c.p[17]
	return xr, xl
}

func (c *Cipher) decrypt(xl, xr uint32) (uint32, uint32) {
	for i := 17; i > 1; i -= 2 {
		xl ^= c.p[i]
		xr ^= c.f(xl)
		xr ^= c.p[i-1]
		xl ^= c.f(xr)
	}
	xl ^= c.p[1]
	xr ^= c.p[0]
	return xr, xl
}

func (c *Cipher) expandKey(key []byte) {
	c.p = pi
	c.s0, c.s1, c.s2, c.s3 = s0, s1, s2, s3

	j := 0
	for i := 0; i < 18; i++ {
		var d uint32
		for k := 0; k < 4; k++ {
			d = d<<8 | uint32(key[j])
			j++
			if j >= len(key) {
				j = 0
			}
		}
		c.p[i] ^= d
	}

	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l, r = c.encrypt(l, r)
		c.p[i], c.p[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = c.encrypt(l, r)
		c.s0[i], c.s0[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = c.encrypt(l, r)
		c.s1[i], c.s1[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = c.encrypt(l, r)
		c.s2[i], c.s2[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = c.encrypt(l, r)
		c.s3[i], c.s3[i+1] = l, r
	}
}

// Compile-time interface check.
var _ cipher.Block = (*Cipher)(nil)
