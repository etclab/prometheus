// Package clusion is a Go port of (part of) the Clusion searchable symmetric
// encryption (SSE) library. It implements the static 2Lev scheme of Cash et
// al. (NDSS'14) in both response-revealing (RR2Lev) and response-hiding
// (RH2Lev) flavours, plus the add-only dynamic variant DynRH2Lev.
//
// This file ports the subset of org.crypto.sse.CryptoPrimitives that the 2Lev
// family needs: PBKDF2 key derivation, AES-CMAC, HMAC-SHA256, AES-CTR string
// encryption, secure random bytes, and the bit helpers used for array-slot
// selection. See docs/01-PORTING-NOTES.md for the design rationale; ciphertexts
// are intentionally NOT byte-compatible with the Java implementation.
package clusion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
)

// ivSize is the AES block size in bytes; CTR uses it as the initial counter.
const ivSize = 16

// KeyGen derives a raw symmetric key from a password using PBKDF2-HMAC-SHA1,
// mirroring CryptoPrimitives.keyGenSetM. keySize is in bits (e.g. 256), so the
// returned key is keySize/8 bytes long.
func KeyGen(keySize int, password string, salt []byte, iterations int) ([]byte, error) {
	return pbkdf2.Key(sha1.New, password, salt, iterations, keySize/8)
}

// GenerateHmac returns HMAC-SHA256(key, msg) — 32 bytes. Mirrors
// CryptoPrimitives.generateHmac. RR2Lev derives its tags and AES keys with it.
func GenerateHmac(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

// GenerateCmac returns AES-CMAC(key, msg) — 16 bytes (one AES block). Mirrors
// CryptoPrimitives.generateCmac (BouncyCastle CMac/AESFastEngine).
// RH2Lev/DynRH2Lev derive their tags and AES keys with it.
func GenerateCmac(key []byte, msg string) []byte {
	out, err := aesCMAC(key, []byte(msg))
	if err != nil {
		// key length is always a valid AES size in this library, so this
		// cannot happen at runtime; surface it loudly if it ever does.
		panic(fmt.Sprintf("clusion: AES-CMAC: %v", err))
	}
	return out
}

// aesCMAC implements AES-CMAC (RFC 4493 / NIST SP 800-38B).
func aesCMAC(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize() // 16

	// Subkey generation: L = AES_K(0^bs), then K1, K2 via shift + conditional Rb.
	l := make([]byte, bs)
	block.Encrypt(l, l)
	k1 := shiftLeftXorRb(l)
	k2 := shiftLeftXorRb(k1)

	// Determine the last block: complete -> XOR K1; otherwise pad 10* -> XOR K2.
	n := (len(msg) + bs - 1) / bs
	var last []byte
	complete := len(msg) > 0 && len(msg)%bs == 0
	if n == 0 {
		n = 1
		complete = false
	}
	if complete {
		last = xorBytes(msg[(n-1)*bs:], k1)
	} else {
		rem := msg[(n-1)*bs:]
		padded := make([]byte, bs)
		copy(padded, rem)
		padded[len(rem)] = 0x80
		last = xorBytes(padded, k2)
	}

	// CBC-MAC with a zero IV over the first n-1 blocks, then the prepared last.
	x := make([]byte, bs)
	for i := 0; i < n-1; i++ {
		y := xorBytes(x, msg[i*bs:(i+1)*bs])
		block.Encrypt(x, y)
	}
	y := xorBytes(x, last)
	out := make([]byte, bs)
	block.Encrypt(out, y)
	return out, nil
}

// shiftLeftXorRb computes (in << 1), XORing the constant Rb (0x87) into the last
// byte when the high bit of in[0] was set. Used for CMAC subkey derivation.
func shiftLeftXorRb(in []byte) []byte {
	out := make([]byte, len(in))
	overflow := byte(0)
	for i := len(in) - 1; i >= 0; i-- {
		out[i] = in[i]<<1 | overflow
		overflow = in[i] >> 7
	}
	if in[0]&0x80 != 0 {
		out[len(out)-1] ^= 0x87
	}
	return out
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// RandomBytes returns n cryptographically secure random bytes
// (CryptoPrimitives.randomBytes).
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("clusion: random: %v", err))
	}
	return b
}

// fileIDTerminator marks the end of a packed identifier inside an AES-CTR
// "string" ciphertext; the rest of the fixed-size buffer is zero padding.
const fileIDTerminator = "\t\t\t"

// EncryptAESCTRString encrypts identifier under key with the given 16-byte iv,
// padding to a fixed total length of size bytes, and prepends the iv. Mirrors
// CryptoPrimitives.encryptAES_CTR_String. The fixed size hides the true length.
func EncryptAESCTRString(key, iv []byte, identifier string, size int) ([]byte, error) {
	plain := []byte(identifier + fileIDTerminator)
	if len(plain) > size {
		return nil, fmt.Errorf("clusion: identifier (%d bytes incl. terminator) exceeds size %d", len(plain), size)
	}
	buf := make([]byte, size) // zero-padded
	copy(buf, plain)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ct := make([]byte, size)
	cipher.NewCTR(block, iv).XORKeyStream(ct, buf)

	out := make([]byte, 0, ivSize+size)
	out = append(out, iv...)
	out = append(out, ct...)
	return out, nil
}

// DecryptAESCTRString reverses EncryptAESCTRString, returning the padded
// plaintext (IV stripped). Callers split on fileIDTerminator and take [0] to
// recover the original identifier. Mirrors decryptAES_CTR_String.
func DecryptAESCTRString(input, key []byte) ([]byte, error) {
	if len(input) < ivSize {
		return nil, fmt.Errorf("clusion: ciphertext too short (%d bytes)", len(input))
	}
	iv := input[:ivSize]
	ct := input[ivSize:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCTR(block, iv).XORKeyStream(pt, ct)
	return pt, nil
}

// getBit returns bit pos of data, reading MSB-first within each byte
// (CryptoPrimitives.getBit).
func getBit(data []byte, pos int) int {
	posByte := pos / 8
	posBit := pos % 8
	return int(data[posByte]>>(8-(posBit+1))) & 0x01
}

// getIntFromByte reads numberOfBits bits from byteArray and assembles them
// little-endian (bit i has weight 2^i), matching CryptoPrimitives.getIntFromByte.
func getIntFromByte(byteArray []byte, numberOfBits int) int {
	result := 0
	for i := 0; i < numberOfBits; i++ {
		result += getBit(byteArray, i) << i
	}
	return result
}
