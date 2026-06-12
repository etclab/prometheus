package timecrypt

import (
	"math/big"
)

// HoMACPrime is the default 128-bit field prime 2^128 - 159 used by the
// homomorphic MACs.
var HoMACPrime, _ = new(big.Int).SetString("340282366920938463463374607431768211297", 10)

// HoMACScheme is an additively-homomorphic MAC over Z_p: tags of individual
// messages can be summed and the aggregate tag verifies against the aggregate
// message with only the two boundary keys.
// Port of ch.ethz.dsg.timecrypt.crypto.encryption.hoMAC.IHoMAC.
type HoMACScheme interface {
	NumFieldBits() int
	Prime() *big.Int
	MACKey() *big.Int
	GetMAC(msg *big.Int, id int64) (*big.Int, error)
	GetMACWithKeys(msg, key1, key2 *big.Int) *big.Int
	CheckMAC(msg, mac *big.Int, msgID, msgTo int64) (bool, error)
	CheckMACWithKeys(msg, mac, key1, key2 *big.Int) bool
	KeyRegression() KeyRegression
	AggregateMAC(mac1, mac2 *big.Int) *big.Int
}

// HoMAC tags msg at time id as (k_id - k_(id+1) - msg) * a^-1 mod p where a
// is the secret MAC key. Verification multiplies back by a, so tags telescope
// like HEAC ciphertexts. Port of hoMAC.HoMAC.
type HoMAC struct {
	reg       KeyRegression
	prime     *big.Int
	macKey    *big.Int
	macKeyInv *big.Int
}

// NewHoMAC creates a HoMAC with the default prime.
func NewHoMAC(reg KeyRegression, macKey *big.Int) *HoMAC {
	return NewHoMACWithPrime(reg, macKey, HoMACPrime)
}

// NewHoMACWithPrime creates a HoMAC over Z_prime.
func NewHoMACWithPrime(reg KeyRegression, macKey, prime *big.Int) *HoMAC {
	k := new(big.Int).Mod(macKey, prime)
	return &HoMAC{
		reg:       reg,
		prime:     prime,
		macKey:    k,
		macKeyInv: new(big.Int).ModInverse(k, prime),
	}
}

func (m *HoMAC) NumFieldBits() int          { return m.prime.BitLen() }
func (m *HoMAC) Prime() *big.Int            { return new(big.Int).Set(m.prime) }
func (m *HoMAC) MACKey() *big.Int           { return new(big.Int).Set(m.macKey) }
func (m *HoMAC) KeyRegression() KeyRegression { return m.reg }

func (m *HoMAC) GetMAC(msg *big.Int, id int64) (*big.Int, error) {
	k1, err := m.reg.GetKey(id, m.NumFieldBits())
	if err != nil {
		return nil, err
	}
	k2, err := m.reg.GetKey(id+1, m.NumFieldBits())
	if err != nil {
		return nil, err
	}
	return m.GetMACWithKeys(msg, k1, k2), nil
}

func (m *HoMAC) GetMACWithKeys(msg, key1, key2 *big.Int) *big.Int {
	tag := new(big.Int).Sub(key1, key2)
	tag.Sub(tag, msg)
	tag.Mul(tag, m.macKeyInv)
	return tag.Mod(tag, m.prime)
}

func (m *HoMAC) CheckMAC(msg, mac *big.Int, msgID, msgTo int64) (bool, error) {
	k1, err := m.reg.GetKey(msgID, m.NumFieldBits())
	if err != nil {
		return false, err
	}
	k2, err := m.reg.GetKey(msgTo+1, m.NumFieldBits())
	if err != nil {
		return false, err
	}
	return m.CheckMACWithKeys(msg, new(big.Int).Mod(mac, m.prime), k1, k2), nil
}

func (m *HoMAC) CheckMACWithKeys(msg, mac, key1, key2 *big.Int) bool {
	key := new(big.Int).Sub(key1, key2)
	key.Mod(key, m.prime)
	comp := new(big.Int).Mul(mac, m.macKey)
	comp.Add(comp, msg)
	comp.Mod(comp, m.prime)
	return key.Cmp(comp) == 0
}

func (m *HoMAC) AggregateMAC(mac1, mac2 *big.Int) *big.Int {
	agg := new(big.Int).Add(mac1, mac2)
	return agg.Mod(agg, m.prime)
}

// HomomorphicMAC tags msg at time id as msg*a + k_id - k_(id+1) mod p.
// Port of hoMAC.HomomorphicMAC.
type HomomorphicMAC struct {
	reg    KeyRegression
	prime  *big.Int
	macKey *big.Int
}

// NewHomomorphicMAC creates a HomomorphicMAC with the default prime.
func NewHomomorphicMAC(reg KeyRegression, macKey *big.Int) *HomomorphicMAC {
	return NewHomomorphicMACWithPrime(reg, macKey, HoMACPrime)
}

// NewHomomorphicMACWithPrime creates a HomomorphicMAC over Z_prime.
func NewHomomorphicMACWithPrime(reg KeyRegression, macKey, prime *big.Int) *HomomorphicMAC {
	return &HomomorphicMAC{reg: reg, prime: prime, macKey: macKey}
}

func (m *HomomorphicMAC) NumFieldBits() int          { return m.prime.BitLen() }
func (m *HomomorphicMAC) Prime() *big.Int            { return new(big.Int).Set(m.prime) }
func (m *HomomorphicMAC) MACKey() *big.Int           { return new(big.Int).Set(m.macKey) }
func (m *HomomorphicMAC) KeyRegression() KeyRegression { return m.reg }

func (m *HomomorphicMAC) GetMAC(msg *big.Int, id int64) (*big.Int, error) {
	k1, err := m.reg.GetKey(id, m.NumFieldBits())
	if err != nil {
		return nil, err
	}
	k2, err := m.reg.GetKey(id+1, m.NumFieldBits())
	if err != nil {
		return nil, err
	}
	return m.GetMACWithKeys(msg, k1, k2), nil
}

func (m *HomomorphicMAC) GetMACWithKeys(msg, key1, key2 *big.Int) *big.Int {
	tag := new(big.Int).Mul(msg, m.macKey)
	tag.Mod(tag, m.prime)
	tag.Add(tag, key1)
	tag.Sub(tag, key2)
	return tag.Mod(tag, m.prime)
}

func (m *HomomorphicMAC) CheckMAC(msg, mac *big.Int, msgID, msgTo int64) (bool, error) {
	k1, err := m.reg.GetKey(msgID, m.NumFieldBits())
	if err != nil {
		return false, err
	}
	k2, err := m.reg.GetKey(msgTo+1, m.NumFieldBits())
	if err != nil {
		return false, err
	}
	return m.CheckMACWithKeys(msg, mac, k1, k2), nil
}

func (m *HomomorphicMAC) CheckMACWithKeys(msg, mac, key1, key2 *big.Int) bool {
	tmpMac := mac
	if mac.Cmp(m.prime) >= 0 {
		tmpMac = new(big.Int).Mod(mac, m.prime)
	}
	comp := m.GetMACWithKeys(msg, key1, key2)
	return tmpMac.Cmp(comp) == 0
}

func (m *HomomorphicMAC) AggregateMAC(mac1, mac2 *big.Int) *big.Int {
	agg := new(big.Int).Add(mac1, mac2)
	return agg.Mod(agg, m.prime)
}
