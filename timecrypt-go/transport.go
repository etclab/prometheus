package timecrypt

import (
	"math"
	"math/big"
)

// Transport helpers for carrying HEAC ciphertexts through systems that only
// move float64 values (e.g. the Prometheus text exposition format and XOR
// chunk storage), where the int64-bits trick (math.Float64frombits) is unsafe
// because ~1/2048 of bit patterns are NaN/Inf and do not round-trip through a
// text encode/parse cycle.
//
// The contract is: choose a HEAC modulus M = 2^modBits with modBits <= 52, so
// every residue in [0, M) is an exact, non-negative integer that float64
// represents without loss. ResidueToFloat / FloatToResidue move such a residue
// through a float64; SignedFromResidue recovers a two's-complement signed value
// after decryption (the library's HEACBigInt.AdaptToLong assumes M = 2^64 and
// cannot map negatives for a small modulus).

// MaxTransportModBits is the largest HEAC modulus bit width whose residues are
// guaranteed to survive a float64 round-trip exactly (2^52 < 2^53, the float64
// exact-integer limit).
const MaxTransportModBits = 52

// ResidueToFloat encodes a ciphertext residue in [0, 2^52) as an exact float64.
// It panics if the residue does not fit, since that would corrupt the value.
func ResidueToFloat(residue *big.Int) float64 {
	if residue.Sign() < 0 || residue.BitLen() > MaxTransportModBits {
		panic("timecrypt: residue out of float64-exact range; use modBits <= 52")
	}
	return float64(residue.Uint64())
}

// FloatToResidue recovers the exact integer residue from a float64 produced by
// ResidueToFloat (after it has been carried through text exposition and chunk
// storage).
func FloatToResidue(f float64) *big.Int {
	return new(big.Int).SetUint64(uint64(math.Round(f)))
}

// SignedFromResidue interprets a decrypted residue in [0, 2^modBits) as a
// two's-complement signed integer: residues at or above 2^(modBits-1) are
// negative. This is the small-modulus analogue of HEACBigInt.AdaptToLong.
func SignedFromResidue(residue *big.Int, modBits int) int64 {
	half := new(big.Int).Lsh(big.NewInt(1), uint(modBits-1))
	if residue.Cmp(half) >= 0 {
		mod := new(big.Int).Lsh(big.NewInt(1), uint(modBits))
		return new(big.Int).Sub(residue, mod).Int64()
	}
	return residue.Int64()
}
