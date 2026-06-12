package timecrypt

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
)

// Key derivation helpers for metadata encryption keys and MAC keys.
// Port of ch.ethz.dsg.timecrypt.crypto.keymanagement.KeyUtil.
//
// Derived keys are domain-separated by the PRF input: encryption keys use
// 0xFF^8 || id (big-endian), MAC keys use id (big-endian) || 0xFF^8, and the
// "default" key (used for leaf-seed -> key derivation in the regression tree)
// uses 0xFF^16.

// EncKeyDerivationInput builds the PRF input for deriving an encryption key
// for the given metadata slot id.
func EncKeyDerivationInput(id int64) []byte {
	in := make([]byte, 16)
	for i := 0; i < 8; i++ {
		in[i] = 0xFF
	}
	binary.BigEndian.PutUint64(in[8:], uint64(id))
	return in
}

// MacKeyDerivationInput builds the PRF input for deriving a MAC key for the
// given metadata slot id.
func MacKeyDerivationInput(id int64) []byte {
	in := make([]byte, 16)
	binary.BigEndian.PutUint64(in[:8], uint64(id))
	for i := 8; i < 16; i++ {
		in[i] = 0xFF
	}
	return in
}

func defaultKeyDerivationInput() []byte {
	in := make([]byte, 16)
	for i := range in {
		in[i] = 0xFF
	}
	return in
}

// DeriveKey derives a bits-sized key from a seed: the 128-bit PRF output is
// split into 128/bits partitions which are XOR-folded together.
func DeriveKey(prf PRF, seed, input []byte, bits int) *big.Int {
	key := prf.Apply(seed, input)
	if (len(key)*8)%bits != 0 {
		panic(fmt.Sprintf("timecrypt: key of %d bits cannot be derived from a %d-byte PRF output", bits, len(key)))
	}
	numPartitions := len(key) * 8 / bits
	if numPartitions < 2 {
		return new(big.Int).SetBytes(key)
	}
	partLen := bits / 8
	cur := new(big.Int).SetBytes(key[:partLen])
	part := new(big.Int)
	for i := 1; i < numPartitions; i++ {
		part.SetBytes(key[i*partLen : (i+1)*partLen])
		cur.Xor(cur, part)
	}
	return cur
}

// DeriveKeyForID derives a bits-sized encryption (forEnc) or MAC key for a
// metadata slot from a leaf seed.
func DeriveKeyForID(prf PRF, seed []byte, forEnc bool, metaID int64, bits int) *big.Int {
	if forEnc {
		return DeriveKey(prf, seed, EncKeyDerivationInput(metaID), bits)
	}
	return DeriveKey(prf, seed, MacKeyDerivationInput(metaID), bits)
}

// DeriveKeyDefault derives a bits-sized key from a seed with the default
// (all-0xFF) PRF input.
func DeriveKeyDefault(prf PRF, seed []byte, bits int) *big.Int {
	return DeriveKey(prf, seed, defaultKeyDerivationInput(), bits)
}

// DeriveKeyLong derives an int64 key: the 128-bit PRF output XOR-folded into
// 64 bits, interpreted big-endian.
func DeriveKeyLong(prf PRF, seed, input []byte) int64 {
	key := prf.Apply(seed, input)
	var out [8]byte
	copy(out[:], key[:8])
	for i := 8; i < len(key); i++ {
		out[i-8] ^= key[i]
	}
	return int64(binary.BigEndian.Uint64(out[:]))
}

// DeriveKeyLongForID derives an int64 encryption (forEnc) or MAC key for a
// metadata slot from a leaf seed.
func DeriveKeyLongForID(prf PRF, seed []byte, forEnc bool, metaID int64) int64 {
	if forEnc {
		return DeriveKeyLong(prf, seed, EncKeyDerivationInput(metaID))
	}
	return DeriveKeyLong(prf, seed, MacKeyDerivationInput(metaID))
}

// DeriveKeyLongDefault derives an int64 key with the default (all-0xFF) input.
func DeriveKeyLongDefault(prf PRF, seed []byte) int64 {
	return DeriveKeyLong(prf, seed, defaultKeyDerivationInput())
}

// DeriveCombinedKey derives a key from two seeds (used for per-chunk AES keys
// so that a chunk key reveals nothing about either adjacent seed).
func DeriveCombinedKey(prf PRF, key1, key2 []byte) []byte {
	if len(key1) != len(key2) {
		panic("timecrypt: cannot create a combined key from keys with different length")
	}
	inputKey := make([]byte, len(key1))
	for i := range key1 {
		inputKey[i] = key1[i] ^ key2[i]
	}
	return prf.Apply(inputKey, EncKeyDerivationInput(0))
}

// GenerateKey returns numBytes of cryptographically random key material.
func GenerateKey(numBytes int) ([]byte, error) {
	key := make([]byte, numBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateMACKey returns a random MAC key in Z_fieldPrime.
func GenerateMACKey(numBits int, fieldPrime *big.Int) (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), uint(numBits))
	k, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return k.Mod(k, fieldPrime), nil
}

// bigIntFromSignedBytes interprets b as a big-endian two's-complement signed
// integer (Java's new BigInteger(byte[]) semantics).
func bigIntFromSignedBytes(b []byte) *big.Int {
	i := new(big.Int).SetBytes(b)
	if len(b) > 0 && b[0]&0x80 != 0 {
		i.Sub(i, new(big.Int).Lsh(big.NewInt(1), uint(len(b)*8)))
	}
	return i
}
