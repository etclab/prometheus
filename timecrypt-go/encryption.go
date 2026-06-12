package timecrypt

import (
	"errors"
	"math/big"
)

// ErrMACCheckFailed is returned when an authenticated decryption fails
// verification. Port of encryption.MACCheckFailed.
var ErrMACCheckFailed = errors.New("timecrypt: MAC check failed")

// The TimeCryptEncryption* types are the client-facing schemes used for the
// per-chunk metadata digests (SUM/COUNT/... slots). A value is addressed by
// (timeID, metadataID): timeID selects the bracketing leaf seeds of the
// key-regression tree, metadataID domain-separates the keys of the different
// metadata slots sharing one time step.

// TimeCryptEncryptionLong is the int64 HEAC scheme without authentication
// (Java scheme LONG). Port of TimeCryptEncryptionLong.
type TimeCryptEncryptionLong struct {
	enc *HEACLong
	reg KeyRegression
}

// NewTimeCryptEncryptionLong creates the scheme on top of a key regression.
func NewTimeCryptEncryptionLong(reg KeyRegression) *TimeCryptEncryptionLong {
	return &TimeCryptEncryptionLong{enc: NewHEACLong(reg), reg: reg}
}

func (t *TimeCryptEncryptionLong) encrypt(msg int64, seed1, seed2 []byte, metadataID int64) int64 {
	return t.enc.EncryptWithKeys(msg,
		DeriveKeyLongForID(t.reg.PRF(), seed1, true, metadataID),
		DeriveKeyLongForID(t.reg.PRF(), seed2, true, metadataID))
}

func (t *TimeCryptEncryptionLong) decrypt(ct int64, seed1, seed2 []byte, metadataID int64) int64 {
	return t.enc.DecryptWithKeys(ct,
		DeriveKeyLongForID(t.reg.PRF(), seed1, true, metadataID),
		DeriveKeyLongForID(t.reg.PRF(), seed2, true, metadataID))
}

func (t *TimeCryptEncryptionLong) seeds(id1, id2 int64) ([]byte, []byte, error) {
	s1, err := t.reg.GetSeed(id1)
	if err != nil {
		return nil, nil, err
	}
	s2, err := t.reg.GetSeed(id2)
	if err != nil {
		return nil, nil, err
	}
	return s1, s2, nil
}

// EncryptMetadata encrypts msg at (timeID, metadataID).
func (t *TimeCryptEncryptionLong) EncryptMetadata(msg, timeID, metadataID int64) (int64, error) {
	s1, s2, err := t.seeds(timeID, timeID+1)
	if err != nil {
		return 0, err
	}
	return t.encrypt(msg, s1, s2, metadataID), nil
}

// EncryptMetadataCached is EncryptMetadata with seed caching across calls for
// the same timeID.
func (t *TimeCryptEncryptionLong) EncryptMetadataCached(msg, timeID, metadataID int64, ck *CachedKeys) (int64, error) {
	if !ck.ContainsKeys() {
		var err error
		if ck.K1, ck.K2, err = t.seeds(timeID, timeID+1); err != nil {
			return 0, err
		}
	}
	return t.encrypt(msg, ck.K1, ck.K2, metadataID), nil
}

// DecryptMetadata decrypts a (possibly summed) ciphertext spanning time ids
// [timeIDFrom, timeIDTo] for one metadata slot.
func (t *TimeCryptEncryptionLong) DecryptMetadata(ct, timeIDFrom, timeIDTo, metadataID int64) (int64, error) {
	s1, s2, err := t.seeds(timeIDFrom, timeIDTo+1)
	if err != nil {
		return 0, err
	}
	return t.decrypt(ct, s1, s2, metadataID), nil
}

// BatchEncryptMetadata encrypts one value per metadata slot at timeID.
func (t *TimeCryptEncryptionLong) BatchEncryptMetadata(msgs []int64, timeID int64, metadataIDs []int64) ([]int64, error) {
	s1, s2, err := t.seeds(timeID, timeID+1)
	if err != nil {
		return nil, err
	}
	out := make([]int64, len(msgs))
	for i, msg := range msgs {
		out[i] = t.encrypt(msg, s1, s2, metadataIDs[i])
	}
	return out, nil
}

// BatchDecryptMetadata decrypts one aggregate per metadata slot over
// [timeIDFrom, timeIDTo].
func (t *TimeCryptEncryptionLong) BatchDecryptMetadata(cts []int64, timeIDFrom, timeIDTo int64, metadataIDs []int64) ([]int64, error) {
	s1, s2, err := t.seeds(timeIDFrom, timeIDTo+1)
	if err != nil {
		return nil, err
	}
	out := make([]int64, len(cts))
	for i, ct := range cts {
		out[i] = t.decrypt(ct, s1, s2, metadataIDs[i])
	}
	return out, nil
}

// TCAuthLongCiphertext is an int64 HEAC ciphertext with a homomorphic auth
// tag. Aggregation adds both components.
type TCAuthLongCiphertext struct {
	Ciphertext int64
	AuthCode   *big.Int
}

// NewTCAuthLongCiphertext returns a zero aggregate to AddMerge into.
func NewTCAuthLongCiphertext() *TCAuthLongCiphertext {
	return &TCAuthLongCiphertext{Ciphertext: 0, AuthCode: new(big.Int)}
}

// Add returns the homomorphic sum of two authenticated ciphertexts.
func (c *TCAuthLongCiphertext) Add(other *TCAuthLongCiphertext) *TCAuthLongCiphertext {
	return &TCAuthLongCiphertext{
		Ciphertext: c.Ciphertext + other.Ciphertext,
		AuthCode:   new(big.Int).Add(c.AuthCode, other.AuthCode),
	}
}

// AddMerge adds other into c in place.
func (c *TCAuthLongCiphertext) AddMerge(other *TCAuthLongCiphertext) {
	c.Ciphertext += other.Ciphertext
	c.AuthCode = new(big.Int).Add(c.AuthCode, other.AuthCode)
}

// TimeCryptEncryptionLongPlus is TimeCryptEncryptionLong with homomorphic
// MACs over the plaintexts (Java scheme LONG_MAC).
// Port of TimeCryptEncryptionLongPlus.
type TimeCryptEncryptionLongPlus struct {
	enc *HEACLong
	mac *HoMAC
	reg KeyRegression
}

// NewTimeCryptEncryptionLongPlus creates the authenticated int64 scheme.
func NewTimeCryptEncryptionLongPlus(reg KeyRegression, macKey *big.Int) *TimeCryptEncryptionLongPlus {
	return &TimeCryptEncryptionLongPlus{enc: NewHEACLong(reg), mac: NewHoMAC(reg, macKey), reg: reg}
}

func (t *TimeCryptEncryptionLongPlus) encrypt(msg int64, seed1, seed2 []byte, metadataID int64) *TCAuthLongCiphertext {
	prf := t.reg.PRF()
	ct := t.enc.EncryptWithKeys(msg,
		DeriveKeyLongForID(prf, seed1, true, metadataID),
		DeriveKeyLongForID(prf, seed2, true, metadataID))
	tag := t.mac.GetMACWithKeys(big.NewInt(msg),
		DeriveKeyForID(prf, seed1, false, metadataID, t.mac.NumFieldBits()),
		DeriveKeyForID(prf, seed2, false, metadataID, t.mac.NumFieldBits()))
	return &TCAuthLongCiphertext{Ciphertext: ct, AuthCode: tag}
}

func (t *TimeCryptEncryptionLongPlus) decrypt(msg *TCAuthLongCiphertext, seed1, seed2 []byte, metadataID int64) (int64, error) {
	prf := t.reg.PRF()
	plain := t.enc.DecryptWithKeys(msg.Ciphertext,
		DeriveKeyLongForID(prf, seed1, true, metadataID),
		DeriveKeyLongForID(prf, seed2, true, metadataID))
	ok := t.mac.CheckMACWithKeys(big.NewInt(plain), msg.AuthCode,
		DeriveKeyForID(prf, seed1, false, metadataID, t.mac.NumFieldBits()),
		DeriveKeyForID(prf, seed2, false, metadataID, t.mac.NumFieldBits()))
	if !ok {
		return 0, ErrMACCheckFailed
	}
	return plain, nil
}

func (t *TimeCryptEncryptionLongPlus) seeds(id1, id2 int64) ([]byte, []byte, error) {
	s1, err := t.reg.GetSeed(id1)
	if err != nil {
		return nil, nil, err
	}
	s2, err := t.reg.GetSeed(id2)
	if err != nil {
		return nil, nil, err
	}
	return s1, s2, nil
}

// EncryptMetadata encrypts and authenticates msg at (timeID, metadataID).
func (t *TimeCryptEncryptionLongPlus) EncryptMetadata(msg, timeID, metadataID int64) (*TCAuthLongCiphertext, error) {
	s1, s2, err := t.seeds(timeID, timeID+1)
	if err != nil {
		return nil, err
	}
	return t.encrypt(msg, s1, s2, metadataID), nil
}

// EncryptMetadataCached is EncryptMetadata with seed caching.
func (t *TimeCryptEncryptionLongPlus) EncryptMetadataCached(msg, timeID, metadataID int64, ck *CachedKeys) (*TCAuthLongCiphertext, error) {
	if !ck.ContainsKeys() {
		var err error
		if ck.K1, ck.K2, err = t.seeds(timeID, timeID+1); err != nil {
			return nil, err
		}
	}
	return t.encrypt(msg, ck.K1, ck.K2, metadataID), nil
}

// DecryptMetadata verifies and decrypts a (possibly summed) authenticated
// ciphertext spanning [timeIDFrom, timeIDTo].
func (t *TimeCryptEncryptionLongPlus) DecryptMetadata(msg *TCAuthLongCiphertext, timeIDFrom, timeIDTo, metadataID int64) (int64, error) {
	s1, s2, err := t.seeds(timeIDFrom, timeIDTo+1)
	if err != nil {
		return 0, err
	}
	return t.decrypt(msg, s1, s2, metadataID)
}

// BatchEncryptMetadata encrypts one value per metadata slot at timeID.
func (t *TimeCryptEncryptionLongPlus) BatchEncryptMetadata(msgs []int64, timeID int64, metadataIDs []int64) ([]*TCAuthLongCiphertext, error) {
	s1, s2, err := t.seeds(timeID, timeID+1)
	if err != nil {
		return nil, err
	}
	out := make([]*TCAuthLongCiphertext, len(msgs))
	for i, msg := range msgs {
		out[i] = t.encrypt(msg, s1, s2, metadataIDs[i])
	}
	return out, nil
}

// BatchDecryptMetadata decrypts one aggregate per metadata slot over
// [timeIDFrom, timeIDTo].
func (t *TimeCryptEncryptionLongPlus) BatchDecryptMetadata(msgs []*TCAuthLongCiphertext, timeIDFrom, timeIDTo int64, metadataIDs []int64) ([]int64, error) {
	s1, s2, err := t.seeds(timeIDFrom, timeIDTo+1)
	if err != nil {
		return nil, err
	}
	out := make([]int64, len(msgs))
	for i, msg := range msgs {
		if out[i], err = t.decrypt(msg, s1, s2, metadataIDs[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// TimeCryptEncryptionBI is the big-integer HEAC scheme without authentication
// (Java scheme BIG_INT_128). Port of TimeCryptEncryptionBI.
type TimeCryptEncryptionBI struct {
	enc *HEACBigInt
	reg KeyRegression
}

// NewTimeCryptEncryptionBI creates the scheme with M = 2^numBits.
func NewTimeCryptEncryptionBI(reg KeyRegression, numBits int) *TimeCryptEncryptionBI {
	return &TimeCryptEncryptionBI{enc: NewHEACBigInt(reg, numBits), reg: reg}
}

// NewTimeCryptEncryptionBI128 creates the scheme with the default 128-bit
// message space.
func NewTimeCryptEncryptionBI128(reg KeyRegression) *TimeCryptEncryptionBI {
	return NewTimeCryptEncryptionBI(reg, 128)
}

func (t *TimeCryptEncryptionBI) keys(seed1, seed2 []byte, metadataID int64) (*big.Int, *big.Int) {
	prf := t.reg.PRF()
	return DeriveKeyForID(prf, seed1, true, metadataID, t.enc.NumMBits()),
		DeriveKeyForID(prf, seed2, true, metadataID, t.enc.NumMBits())
}

func (t *TimeCryptEncryptionBI) seeds(id1, id2 int64) ([]byte, []byte, error) {
	s1, err := t.reg.GetSeed(id1)
	if err != nil {
		return nil, nil, err
	}
	s2, err := t.reg.GetSeed(id2)
	if err != nil {
		return nil, nil, err
	}
	return s1, s2, nil
}

// EncryptMetadata encrypts msg at (timeID, metadataID).
func (t *TimeCryptEncryptionBI) EncryptMetadata(msg *big.Int, timeID, metadataID int64) (*big.Int, error) {
	s1, s2, err := t.seeds(timeID, timeID+1)
	if err != nil {
		return nil, err
	}
	k1, k2 := t.keys(s1, s2, metadataID)
	return t.enc.EncryptWithKeys(msg, k1, k2), nil
}

// EncryptMetadataCached is EncryptMetadata with seed caching.
func (t *TimeCryptEncryptionBI) EncryptMetadataCached(msg *big.Int, timeID, metadataID int64, ck *CachedKeys) (*big.Int, error) {
	if !ck.ContainsKeys() {
		var err error
		if ck.K1, ck.K2, err = t.seeds(timeID, timeID+1); err != nil {
			return nil, err
		}
	}
	k1, k2 := t.keys(ck.K1, ck.K2, metadataID)
	return t.enc.EncryptWithKeys(msg, k1, k2), nil
}

// DecryptMetadata decrypts a (possibly summed) ciphertext spanning
// [timeIDFrom, timeIDTo].
func (t *TimeCryptEncryptionBI) DecryptMetadata(msg *big.Int, timeIDFrom, timeIDTo, metadataID int64) (*big.Int, error) {
	s1, s2, err := t.seeds(timeIDFrom, timeIDTo+1)
	if err != nil {
		return nil, err
	}
	k1, k2 := t.keys(s1, s2, metadataID)
	return t.enc.DecryptWithKeys(msg, k1, k2), nil
}

// DecryptMetadataLong decrypts to a signed int64.
func (t *TimeCryptEncryptionBI) DecryptMetadataLong(msg *big.Int, timeIDFrom, timeIDTo, metadataID int64) (int64, error) {
	p, err := t.DecryptMetadata(msg, timeIDFrom, timeIDTo, metadataID)
	if err != nil {
		return 0, err
	}
	return t.enc.AdaptToLong(p), nil
}

// TCAuthBICiphertext is a big-int HEAC ciphertext with a homomorphic auth
// tag. Aggregation adds both components.
type TCAuthBICiphertext struct {
	Ciphertext *big.Int
	AuthCode   *big.Int
}

// NewTCAuthBICiphertext returns a zero aggregate to AddMerge into.
func NewTCAuthBICiphertext() *TCAuthBICiphertext {
	return &TCAuthBICiphertext{Ciphertext: new(big.Int), AuthCode: new(big.Int)}
}

// Add returns the homomorphic sum of two authenticated ciphertexts.
func (c *TCAuthBICiphertext) Add(other *TCAuthBICiphertext) *TCAuthBICiphertext {
	return &TCAuthBICiphertext{
		Ciphertext: new(big.Int).Add(c.Ciphertext, other.Ciphertext),
		AuthCode:   new(big.Int).Add(c.AuthCode, other.AuthCode),
	}
}

// AddMerge adds other into c in place.
func (c *TCAuthBICiphertext) AddMerge(other *TCAuthBICiphertext) {
	c.Ciphertext = new(big.Int).Add(c.Ciphertext, other.Ciphertext)
	c.AuthCode = new(big.Int).Add(c.AuthCode, other.AuthCode)
}

// TimeCryptEncryptionBIPlus is the big-integer HEAC scheme with homomorphic
// MACs over the ciphertexts (Java scheme BIG_INT_128_MAC); M is the MAC field
// prime so ciphertexts and tags live in the same field.
// Port of TimeCryptEncryptionBIPlus.
type TimeCryptEncryptionBIPlus struct {
	enc *HEACBigInt
	mac *HoMAC
	reg KeyRegression
}

// NewTimeCryptEncryptionBIPlus creates the authenticated big-int scheme.
func NewTimeCryptEncryptionBIPlus(reg KeyRegression, macKey *big.Int) *TimeCryptEncryptionBIPlus {
	return &TimeCryptEncryptionBIPlus{
		enc: NewHEACBigIntWithModulus(reg, HoMACPrime),
		mac: NewHoMAC(reg, macKey),
		reg: reg,
	}
}

func (t *TimeCryptEncryptionBIPlus) encKeys(seed1, seed2 []byte, metadataID int64) (*big.Int, *big.Int) {
	prf := t.reg.PRF()
	return DeriveKeyForID(prf, seed1, true, metadataID, t.mac.NumFieldBits()),
		DeriveKeyForID(prf, seed2, true, metadataID, t.mac.NumFieldBits())
}

func (t *TimeCryptEncryptionBIPlus) macKeys(seed1, seed2 []byte, metadataID int64) (*big.Int, *big.Int) {
	prf := t.reg.PRF()
	return DeriveKeyForID(prf, seed1, false, metadataID, t.mac.NumFieldBits()),
		DeriveKeyForID(prf, seed2, false, metadataID, t.mac.NumFieldBits())
}

func (t *TimeCryptEncryptionBIPlus) seeds(id1, id2 int64) ([]byte, []byte, error) {
	s1, err := t.reg.GetSeed(id1)
	if err != nil {
		return nil, nil, err
	}
	s2, err := t.reg.GetSeed(id2)
	if err != nil {
		return nil, nil, err
	}
	return s1, s2, nil
}

func (t *TimeCryptEncryptionBIPlus) encrypt(msg *big.Int, seed1, seed2 []byte, metadataID int64) *TCAuthBICiphertext {
	ek1, ek2 := t.encKeys(seed1, seed2, metadataID)
	ct := t.enc.EncryptWithKeys(msg, ek1, ek2)
	mk1, mk2 := t.macKeys(seed1, seed2, metadataID)
	return &TCAuthBICiphertext{Ciphertext: ct, AuthCode: t.mac.GetMACWithKeys(ct, mk1, mk2)}
}

func (t *TimeCryptEncryptionBIPlus) checkMAC(msg *TCAuthBICiphertext, seed1, seed2 []byte, metadataID int64) error {
	mk1, mk2 := t.macKeys(seed1, seed2, metadataID)
	if !t.mac.CheckMACWithKeys(new(big.Int).Mod(msg.Ciphertext, t.mac.prime), msg.AuthCode, mk1, mk2) {
		return ErrMACCheckFailed
	}
	return nil
}

func (t *TimeCryptEncryptionBIPlus) decrypt(msg *TCAuthBICiphertext, seed1, seed2 []byte, metadataID int64) (*big.Int, error) {
	if err := t.checkMAC(msg, seed1, seed2, metadataID); err != nil {
		return nil, err
	}
	ek1, ek2 := t.encKeys(seed1, seed2, metadataID)
	return t.enc.DecryptWithKeys(msg.Ciphertext, ek1, ek2), nil
}

// EncryptMetadata encrypts and authenticates msg at (timeID, metadataID).
func (t *TimeCryptEncryptionBIPlus) EncryptMetadata(msg *big.Int, timeID, metadataID int64) (*TCAuthBICiphertext, error) {
	s1, s2, err := t.seeds(timeID, timeID+1)
	if err != nil {
		return nil, err
	}
	return t.encrypt(msg, s1, s2, metadataID), nil
}

// EncryptMetadataCached is EncryptMetadata with seed caching.
func (t *TimeCryptEncryptionBIPlus) EncryptMetadataCached(msg *big.Int, timeID, metadataID int64, ck *CachedKeys) (*TCAuthBICiphertext, error) {
	if !ck.ContainsKeys() {
		var err error
		if ck.K1, ck.K2, err = t.seeds(timeID, timeID+1); err != nil {
			return nil, err
		}
	}
	return t.encrypt(msg, ck.K1, ck.K2, metadataID), nil
}

// BatchEncryptMetadata encrypts one value per metadata slot at timeID.
func (t *TimeCryptEncryptionBIPlus) BatchEncryptMetadata(msgs []*big.Int, timeID int64, metadataIDs []int64) ([]*TCAuthBICiphertext, error) {
	s1, s2, err := t.seeds(timeID, timeID+1)
	if err != nil {
		return nil, err
	}
	out := make([]*TCAuthBICiphertext, len(msgs))
	for i, msg := range msgs {
		out[i] = t.encrypt(msg, s1, s2, metadataIDs[i])
	}
	return out, nil
}

// DecryptMetadata verifies and decrypts a (possibly summed) authenticated
// ciphertext spanning [timeIDFrom, timeIDTo].
func (t *TimeCryptEncryptionBIPlus) DecryptMetadata(msg *TCAuthBICiphertext, timeIDFrom, timeIDTo, metadataID int64) (*big.Int, error) {
	s1, s2, err := t.seeds(timeIDFrom, timeIDTo+1)
	if err != nil {
		return nil, err
	}
	return t.decrypt(msg, s1, s2, metadataID)
}

// DecryptMetadataLong verifies and decrypts to a signed int64.
func (t *TimeCryptEncryptionBIPlus) DecryptMetadataLong(msg *TCAuthBICiphertext, timeIDFrom, timeIDTo, metadataID int64) (int64, error) {
	p, err := t.DecryptMetadata(msg, timeIDFrom, timeIDTo, metadataID)
	if err != nil {
		return 0, err
	}
	return t.enc.AdaptToLong(p), nil
}
