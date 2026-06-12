// Package timecrypt is a Go port of the TimeCrypt crypto core
// (https://github.com/TimeCrypt/timecrypt, NSDI'20 Burkhalter et al.):
// PRF-tree key regression and the HEAC additively-homomorphic encryption
// scheme with optional homomorphic MACs, plus AES-GCM chunk encryption.
//
// Encryption happens entirely client-side; an untrusted server can sum
// HEAC ciphertexts over arbitrary time ranges without learning plaintexts.
package timecrypt

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
)

// PRF is a pseudo-random function family used to derive seeds and keys.
// Port of ch.ethz.dsg.timecrypt.crypto.prf.IPRF.
type PRF interface {
	// Apply evaluates the PRF keyed with prfKey on input. Input length must
	// be a multiple of the block size (in practice always one 16-byte block).
	Apply(prfKey, input []byte) []byte
	// ApplyInt evaluates the PRF on the integer input packed big-endian into
	// the last 4 bytes of an otherwise-zero block.
	ApplyInt(prfKey []byte, input int32) []byte
	// MultiApply chains ApplyInt: the output for one input keys the next.
	MultiApply(prfKey []byte, inputs []int32) []byte
}

// AESPRF implements PRF as raw AES-128 block encryption (AES-ECB over one
// block), matching the Java PRFAes/PRFAesNi implementations bit for bit.
type AESPRF struct{}

// NewAESPRF returns the default PRF.
func NewAESPRF() AESPRF { return AESPRF{} }

func (AESPRF) Apply(prfKey, input []byte) []byte {
	block, err := aes.NewCipher(prfKey)
	if err != nil {
		panic(fmt.Sprintf("timecrypt: bad PRF key: %v", err))
	}
	if len(input)%aes.BlockSize != 0 {
		panic("timecrypt: PRF input is not a multiple of the AES block size")
	}
	out := make([]byte, len(input))
	for i := 0; i < len(input); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], input[i:i+aes.BlockSize])
	}
	return out
}

func (p AESPRF) ApplyInt(prfKey []byte, input int32) []byte {
	var data [aes.BlockSize]byte
	binary.BigEndian.PutUint32(data[12:], uint32(input))
	return p.Apply(prfKey, data[:])
}

func (p AESPRF) MultiApply(prfKey []byte, inputs []int32) []byte {
	cur := prfKey
	for _, in := range inputs {
		cur = p.ApplyInt(cur, in)
	}
	return cur
}
