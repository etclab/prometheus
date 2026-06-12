package timecrypt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"math/rand"
	"testing"
)

// Ports of timecrypt-crypto/src/test/java/TestTimeCryptCrypto.java.

func testKeyRegression(t *testing.T, depth int) *TreeKeyRegression {
	t.Helper()
	// Java getNewDefaultTESTKeyRegression: all-zero 16-byte root seed.
	return NewTreeKeyRegression(NewAESPRF(), make([]byte, 16), depth, 2)
}

// FIPS-197 appendix C.1 known-answer test pins the PRF to AES-128.
func TestPRFKnownAnswer(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	pt, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	want, _ := hex.DecodeString("69c4e0d86a7b0430d8cdb78070b4c55a")
	got := NewAESPRF().Apply(key, pt)
	if !bytes.Equal(got, want) {
		t.Fatalf("PRF(key, pt) = %x, want %x", got, want)
	}
}

func TestPRFApplyIntPacksBigEndianTail(t *testing.T) {
	prf := NewAESPRF()
	key := make([]byte, 16)
	input := int32(-559038737) // 0xDEADBEEF
	block := make([]byte, 16)
	copy(block[12:], []byte{0xDE, 0xAD, 0xBE, 0xEF})
	if !bytes.Equal(prf.ApplyInt(key, input), prf.Apply(key, block)) {
		t.Fatal("ApplyInt does not match Apply on a manually packed block")
	}
}

func TestTreeKeyRegressionGetKeysMatchesGetKey(t *testing.T) {
	depth := 15
	reg := testKeyRegression(t, depth)
	rangeKeys, err := reg.GetKeys(0, 1<<(depth-1), 64)
	if err != nil {
		t.Fatal(err)
	}
	for i, k := range rangeKeys {
		single, err := reg.GetKey(int64(i), 64)
		if err != nil {
			t.Fatal(err)
		}
		if k.Cmp(single) != 0 {
			t.Fatalf("key %d: GetKeys=%v GetKey=%v", i, k, single)
		}
	}
}

func TestHEACBigIntSum(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	reg := testKeyRegression(t, 20)
	heac := NewHEACBigInt(reg, 64)
	for i := 0; i < 10; i++ {
		m0 := int64(rng.Int31() / 4)
		m1 := int64(rng.Int31() / 4)
		c1, err := heac.Encrypt(big.NewInt(m0), 0)
		if err != nil {
			t.Fatal(err)
		}
		c2, err := heac.Encrypt(big.NewInt(m1), 1)
		if err != nil {
			t.Fatal(err)
		}
		res, err := heac.DecryptLong(new(big.Int).Add(c1, c2), 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		if res != m0+m1 {
			t.Fatalf("decrypted %d, want %d", res, m0+m1)
		}
	}
}

func TestHEACBigIntLargeSum(t *testing.T) {
	const iter = 1000
	rng := rand.New(rand.NewSource(1))
	reg := testKeyRegression(t, 20)
	heac := NewHEACBigInt(reg, 64)

	numbers := make([]*big.Int, iter)
	ciphertexts := make([]*big.Int, iter)
	for i := range numbers {
		// Negative and positive values, small enough that the sum fits.
		numbers[i] = big.NewInt(rng.Int63()/(iter*2) - rng.Int63()/(iter*4))
		var err error
		if ciphertexts[i], err = heac.Encrypt(numbers[i], int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	sumPlain := new(big.Int)
	sumCi := new(big.Int)
	for i := 0; i < iter; i++ {
		sumPlain.Add(sumPlain, numbers[i])
		sumCi.Add(sumCi, ciphertexts[i])
		sumCi.Mod(sumCi, heac.M())
		dec, err := heac.DecryptLong(sumCi, 0, int64(i))
		if err != nil {
			t.Fatal(err)
		}
		if sumPlain.Cmp(big.NewInt(dec)) != 0 {
			t.Fatalf("at %d: decrypted %d, want %v", i, dec, sumPlain)
		}
	}
}

func TestHEACLongSum(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	reg := testKeyRegression(t, 20)
	heac := NewHEACLong(reg)
	for i := 0; i < 10; i++ {
		m0 := rng.Int63()/4 - rng.Int63()/8
		m1 := rng.Int63()/4 - rng.Int63()/8
		c1, err := heac.Encrypt(m0, 0)
		if err != nil {
			t.Fatal(err)
		}
		c2, err := heac.Encrypt(m1, 1)
		if err != nil {
			t.Fatal(err)
		}
		res, err := heac.Decrypt(c1+c2, 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		if res != m0+m1 {
			t.Fatalf("decrypted %d, want %d", res, m0+m1)
		}
	}
}

func TestHEACLongLargeSum(t *testing.T) {
	const iter = 1000
	rng := rand.New(rand.NewSource(1))
	reg := testKeyRegression(t, 20)
	heac := NewHEACLong(reg)

	var sumPlain, sumCi int64
	for i := 0; i < iter; i++ {
		n := rng.Int63()/(iter*2) - rng.Int63()/(iter*4)
		c, err := heac.Encrypt(n, int64(i))
		if err != nil {
			t.Fatal(err)
		}
		sumPlain += n
		sumCi += c
		dec, err := heac.Decrypt(sumCi, 0, int64(i))
		if err != nil {
			t.Fatal(err)
		}
		if dec != sumPlain {
			t.Fatalf("at %d: decrypted %d, want %d", i, dec, sumPlain)
		}
	}
}

func randMACKey(t *testing.T, rng *rand.Rand) *big.Int {
	t.Helper()
	b := make([]byte, 16)
	rng.Read(b)
	return new(big.Int).Mod(new(big.Int).SetBytes(b), HoMACPrime)
}

type macScheme interface {
	GetMAC(msg *big.Int, id int64) (*big.Int, error)
	CheckMAC(msg, mac *big.Int, msgID, msgTo int64) (bool, error)
	AggregateMAC(mac1, mac2 *big.Int) *big.Int
}

func testMACBasic(t *testing.T, mac macScheme) {
	t.Helper()
	msg0, msg1 := big.NewInt(10), big.NewInt(12)
	mac0, err := mac.GetMAC(msg0, 2)
	if err != nil {
		t.Fatal(err)
	}
	mac1, err := mac.GetMAC(msg1, 3)
	if err != nil {
		t.Fatal(err)
	}
	aggr := mac.AggregateMAC(mac0, mac1)
	ok, err := mac.CheckMAC(new(big.Int).Add(msg0, msg1), aggr, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("valid aggregate MAC did not verify")
	}
	bad := new(big.Int).Add(aggr, big.NewInt(1))
	ok, err = mac.CheckMAC(new(big.Int).Add(msg0, msg1), bad, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("tampered MAC verified")
	}
}

func testMACSums(t *testing.T, mac macScheme) {
	t.Helper()
	const numMessages = 60
	rng := rand.New(rand.NewSource(3))
	msgs := make([]*big.Int, numMessages)
	macs := make([]*big.Int, numMessages)
	for i := range msgs {
		msgs[i] = big.NewInt(int64(rng.Int31()) - int64(rng.Int31()/2))
		var err error
		if macs[i], err = mac.GetMAC(msgs[i], int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < numMessages; i++ {
		aggrMac := new(big.Int)
		aggrMsg := new(big.Int)
		for j := i; j < numMessages; j++ {
			aggrMac = mac.AggregateMAC(aggrMac, macs[j])
			aggrMsg = mac.AggregateMAC(aggrMsg, new(big.Int).Mod(msgs[j], HoMACPrime))
			ok, err := mac.CheckMAC(aggrMsg, aggrMac, int64(i), int64(j))
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatalf("aggregate MAC over [%d,%d] did not verify", i, j)
			}
		}
	}
}

func TestHomomorphicMAC(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	mac := NewHomomorphicMAC(testKeyRegression(t, 20), randMACKey(t, rng))
	testMACBasic(t, mac)
	testMACSums(t, mac)
}

func TestHoMAC(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	mac := NewHoMAC(testKeyRegression(t, 20), randMACKey(t, rng))
	testMACBasic(t, mac)
	testMACSums(t, mac)
}

func TestTimeCryptEncryptionLongPlusAggregate(t *testing.T) {
	const numMessages = 100
	rng := rand.New(rand.NewSource(4))
	enc := NewTimeCryptEncryptionLongPlus(testKeyRegression(t, 20), randMACKey(t, rng))

	msgs := make([]int64, numMessages)
	encs := make([]*TCAuthLongCiphertext, numMessages)
	for i := range msgs {
		msgs[i] = int64(rng.Int31()) - int64(rng.Int31()/2)
		var err error
		if encs[i], err = enc.EncryptMetadata(msgs[i], int64(i), 0); err != nil {
			t.Fatal(err)
		}
	}

	var aggrMsg int64
	merge := NewTCAuthLongCiphertext()
	for i := range msgs {
		aggrMsg += msgs[i]
		merge.AddMerge(encs[i])
		res, err := enc.DecryptMetadata(merge, 0, int64(i), 0)
		if err != nil {
			t.Fatal(err)
		}
		if res != aggrMsg {
			t.Fatalf("at %d: decrypted %d, want %d", i, res, aggrMsg)
		}
	}
}

func TestTimeCryptEncryptionLongPlusMACFails(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	enc := NewTimeCryptEncryptionLongPlus(testKeyRegression(t, 20), randMACKey(t, rng))
	ciph, err := enc.EncryptMetadata(1, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	ciph.Ciphertext++
	if _, err := enc.DecryptMetadata(ciph, 0, 0, 0); !errors.Is(err, ErrMACCheckFailed) {
		t.Fatalf("got err=%v, want ErrMACCheckFailed", err)
	}
}

func TestTimeCryptEncryptionBIPlusAggregate(t *testing.T) {
	const numMessages = 100
	rng := rand.New(rand.NewSource(6))
	enc := NewTimeCryptEncryptionBIPlus(testKeyRegression(t, 20), randMACKey(t, rng))

	msgs := make([]int64, numMessages)
	encs := make([]*TCAuthBICiphertext, numMessages)
	for i := range msgs {
		msgs[i] = int64(rng.Int31()) - int64(rng.Int31()/2)
		var err error
		if encs[i], err = enc.EncryptMetadata(big.NewInt(msgs[i]), int64(i), 0); err != nil {
			t.Fatal(err)
		}
	}

	var aggrMsg int64
	merge := NewTCAuthBICiphertext()
	for i := range msgs {
		aggrMsg += msgs[i]
		merge.AddMerge(encs[i])
		res, err := enc.DecryptMetadataLong(merge, 0, int64(i), 0)
		if err != nil {
			t.Fatal(err)
		}
		if res != aggrMsg {
			t.Fatalf("at %d: decrypted %d, want %d", i, res, aggrMsg)
		}
	}
}

func TestChunkEncryptionRoundTrip(t *testing.T) {
	skm, err := NewStreamKeyManager(make([]byte, 16), 20)
	if err != nil {
		t.Fatal(err)
	}
	key, err := skm.ChunkEncryptionKey(7)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("a chunk of samples")
	ct, err := EncryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptAESGCM(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round trip mismatch: %q", pt)
	}
	ct[len(ct)-1] ^= 1
	if _, err := DecryptAESGCM(key, ct); err == nil {
		t.Fatal("tampered AES-GCM ciphertext decrypted successfully")
	}
}

func TestFixedPointSumCommutes(t *testing.T) {
	vals := []float64{0.3, 0.7, 0.5, 1.3, -0.25}
	var fixedSum int64
	var floatSum float64
	for _, v := range vals {
		fixedSum += FloatToFixed(v, DefaultFixedPointScale)
		floatSum += v
	}
	if got := FixedToFloat(fixedSum, DefaultFixedPointScale); got != floatSum {
		t.Fatalf("fixed-point sum %v != float sum %v", got, floatSum)
	}
}
