package timecrypt

import (
	"math/big"
)

// HEAC is TimeCrypt's additively-homomorphic encryption scheme
// (Castelluccia-style):
//
//	c_0 = m_0 + k_0 - k_1 (mod M)
//	c_1 = m_1 + k_1 - k_2 (mod M)
//	...
//
// Adjacent keys telescope, so sum(c_i, i=a..b) decrypts with only k_a and
// k_(b+1): an untrusted server can aggregate ciphertexts over arbitrary
// ranges without learning anything.

// HEACLong is HEAC over int64 with natural two's-complement wraparound
// (M = 2^64). Port of HEACEncryptionLong.
type HEACLong struct {
	reg KeyRegression
}

// NewHEACLong creates a HEACLong drawing keys from the given key regression.
func NewHEACLong(reg KeyRegression) *HEACLong {
	return &HEACLong{reg: reg}
}

// NumMBits returns the message-space size in bits.
func (h *HEACLong) NumMBits() int { return 64 }

func (h *HEACLong) deriveKey(id int64) (int64, error) {
	seed, err := h.reg.GetSeed(id)
	if err != nil {
		return 0, err
	}
	return DeriveKeyLongDefault(h.reg.PRF(), seed), nil
}

// EncryptWithKeys encrypts msg under the two bracketing keys.
func (h *HEACLong) EncryptWithKeys(msg, key1, key2 int64) int64 {
	return msg + key1 - key2
}

// Encrypt encrypts msg at time id.
func (h *HEACLong) Encrypt(msg, id int64) (int64, error) {
	k1, err := h.deriveKey(id)
	if err != nil {
		return 0, err
	}
	k2, err := h.deriveKey(id + 1)
	if err != nil {
		return 0, err
	}
	return h.EncryptWithKeys(msg, k1, k2), nil
}

// DecryptWithKeys decrypts a (possibly aggregated) ciphertext with the two
// boundary keys.
func (h *HEACLong) DecryptWithKeys(ciphertext, key1, key2 int64) int64 {
	return ciphertext - key1 + key2
}

// Decrypt decrypts an aggregate over time ids [msgFrom, msgTo] (a single
// message is msgFrom == msgTo).
func (h *HEACLong) Decrypt(ciphertext, msgFrom, msgTo int64) (int64, error) {
	k1, err := h.deriveKey(msgFrom)
	if err != nil {
		return 0, err
	}
	k2, err := h.deriveKey(msgTo + 1)
	if err != nil {
		return 0, err
	}
	return h.DecryptWithKeys(ciphertext, k1, k2), nil
}

// HEACBigInt is HEAC over Z_M with big-integer arithmetic.
// Port of HEACEncryptionBI.
type HEACBigInt struct {
	reg KeyRegression
	m   *big.Int
}

// NewHEACBigInt creates a HEACBigInt with M = 2^mBits.
func NewHEACBigInt(reg KeyRegression, mBits int) *HEACBigInt {
	return &HEACBigInt{reg: reg, m: new(big.Int).Lsh(big.NewInt(1), uint(mBits))}
}

// NewHEACBigIntWithModulus creates a HEACBigInt with an explicit modulus.
func NewHEACBigIntWithModulus(reg KeyRegression, m *big.Int) *HEACBigInt {
	return &HEACBigInt{reg: reg, m: new(big.Int).Set(m)}
}

// M returns the modulus.
func (h *HEACBigInt) M() *big.Int { return new(big.Int).Set(h.m) }

// KeyRegression returns the underlying key regression.
func (h *HEACBigInt) KeyRegression() KeyRegression { return h.reg }

// NumMBits returns the message-space size in bits.
func (h *HEACBigInt) NumMBits() int { return h.m.BitLen() - 1 }

// EncryptWithKeys encrypts msg under the two bracketing keys.
func (h *HEACBigInt) EncryptWithKeys(msg, key1, key2 *big.Int) *big.Int {
	c := new(big.Int).Add(msg, key1)
	c.Sub(c, key2)
	return c.Mod(c, h.m)
}

// Encrypt encrypts msg at time id.
func (h *HEACBigInt) Encrypt(msg *big.Int, id int64) (*big.Int, error) {
	k1, err := h.reg.GetKey(id, h.NumMBits())
	if err != nil {
		return nil, err
	}
	k2, err := h.reg.GetKey(id+1, h.NumMBits())
	if err != nil {
		return nil, err
	}
	return h.EncryptWithKeys(msg, k1, k2), nil
}

// DecryptWithKeys decrypts a (possibly aggregated) ciphertext with the two
// boundary keys.
func (h *HEACBigInt) DecryptWithKeys(ciphertext, key1, key2 *big.Int) *big.Int {
	p := new(big.Int).Sub(ciphertext, key1)
	p.Add(p, key2)
	return p.Mod(p, h.m)
}

// Decrypt decrypts an aggregate over time ids [msgFrom, msgTo].
func (h *HEACBigInt) Decrypt(ciphertext *big.Int, msgFrom, msgTo int64) (*big.Int, error) {
	k1, err := h.reg.GetKey(msgFrom, h.NumMBits())
	if err != nil {
		return nil, err
	}
	k2, err := h.reg.GetKey(msgTo+1, h.NumMBits())
	if err != nil {
		return nil, err
	}
	return h.DecryptWithKeys(ciphertext, k1, k2), nil
}

// adaptForNegNumber maps a mod-M residue back to a signed value: anything
// above maxPosNum is interpreted as negative.
func (h *HEACBigInt) adaptForNegNumber(num, maxPosNum *big.Int) *big.Int {
	if num.Cmp(maxPosNum) > 0 {
		return new(big.Int).Sub(num, h.m)
	}
	return num
}

var (
	maxInt64Big = big.NewInt(int64(^uint64(0) >> 1))
	maxInt32Big = big.NewInt(int64(int32(^uint32(0) >> 1)))
)

// AdaptToLong maps a decrypted residue to a signed int64.
func (h *HEACBigInt) AdaptToLong(value *big.Int) int64 {
	return h.adaptForNegNumber(value, maxInt64Big).Int64()
}

// DecryptLongWithKeys decrypts to a signed int64.
func (h *HEACBigInt) DecryptLongWithKeys(ciphertext, key1, key2 *big.Int) int64 {
	return h.AdaptToLong(h.DecryptWithKeys(ciphertext, key1, key2))
}

// DecryptLong decrypts an aggregate over [msgFrom, msgTo] to a signed int64.
func (h *HEACBigInt) DecryptLong(ciphertext *big.Int, msgFrom, msgTo int64) (int64, error) {
	p, err := h.Decrypt(ciphertext, msgFrom, msgTo)
	if err != nil {
		return 0, err
	}
	return h.AdaptToLong(p), nil
}

// DecryptIntWithKeys decrypts to a signed int32.
func (h *HEACBigInt) DecryptIntWithKeys(ciphertext, key1, key2 *big.Int) int32 {
	return int32(h.adaptForNegNumber(h.DecryptWithKeys(ciphertext, key1, key2), maxInt32Big).Int64())
}

// Add homomorphically adds two ciphertexts.
func (h *HEACBigInt) Add(c1, c2 *big.Int) *big.Int {
	c := new(big.Int).Add(c1, c2)
	return c.Mod(c, h.m)
}
