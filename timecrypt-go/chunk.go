package timecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// AES-GCM encryption for raw chunk payloads, with the 12-byte nonce prefixed
// to the ciphertext (nonce || ciphertext || tag).
// Port of ch.ethz.dsg.timecrypt.crypto.encryption.TimeCryptChunkEncryption.

const gcmNonceSize = 12

// EncryptAESGCM encrypts data under key with a random nonce.
func EncryptAESGCM(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptAESGCM decrypts a nonce-prefixed AES-GCM ciphertext.
func DecryptAESGCM(key, encData []byte) ([]byte, error) {
	if len(encData) < gcmNonceSize {
		return nil, fmt.Errorf("timecrypt: ciphertext shorter than nonce (%d bytes)", len(encData))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, encData[:gcmNonceSize], encData[gcmNonceSize:], nil)
}
