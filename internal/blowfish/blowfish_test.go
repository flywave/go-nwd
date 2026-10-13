package blowfish

import (
	"encoding/hex"
	"testing"
)

// Standard Blowfish test vectors (Schneier); key and plaintext are the
// 8-byte sequences given, expected ciphertext listed per vector.
func TestKnownVectors(t *testing.T) {
	cases := []struct{ key, plain, cipher string }{
		{"0000000000000000", "0000000000000000", "4ef997456198dd78"},
		{"ffffffffffffffff", "ffffffffffffffff", "51866fd5b85ecb8a"},
		{"3000000000000000", "1000000000000001", "7d856f9a613063f2"},
		{"1111111111111111", "1111111111111111", "2466dd878b963c9d"},
	}
	for _, tc := range cases {
		key, _ := hex.DecodeString(tc.key)
		pt, _ := hex.DecodeString(tc.plain)
		want, _ := hex.DecodeString(tc.cipher)

		c, err := NewCipher(key)
		if err != nil {
			t.Fatalf("NewCipher: %v", err)
		}
		var out [8]byte
		c.Encrypt(out[:], pt)
		if hex.EncodeToString(out[:]) != tc.cipher {
			t.Errorf("key=%s plain=%s enc=%x want %x", tc.key, tc.plain, out, want)
		}
		var back [8]byte
		c.Decrypt(back[:], out[:])
		if hex.EncodeToString(back[:]) != tc.plain {
			t.Errorf("decrypt roundtrip key=%s got %x want %x", tc.key, back, pt)
		}
	}
}

func TestKeySize(t *testing.T) {
	if _, err := NewCipher(nil); err == nil {
		t.Error("empty key should fail")
	}
	if _, err := NewCipher(make([]byte, 57)); err == nil {
		t.Error("57-byte key should fail")
	}
	if _, err := NewCipher(make([]byte, 32)); err != nil {
		t.Errorf("32-byte key: %v", err)
	}
}
