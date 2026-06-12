package timecrypt

import (
	"errors"
	"math/big"
)

// StreamKeyManager handles all keys associated with one stream. From the
// stream master key a depth-2 tree derives: leaf 1 = the root of the
// metadata/chunk key-regression tree, leaf 2 = the MAC key, leaf 3 = the
// sharing master key.
// Port of ch.ethz.dsg.timecrypt.crypto.keymanagement.StreamKeyManager.
type StreamKeyManager struct {
	treeKeyRegression *TreeKeyRegression
	macKey            []byte
	sharingMasterKey  []byte
	isMaster          bool
}

// NewStreamKeyManager creates the key hierarchy of a stream owner.
// numKeysDepth is the depth of the per-stream key-regression tree
// (2^numKeysDepth derivable chunk/metadata keys).
func NewStreamKeyManager(streamMasterKey []byte, numKeysDepth int) (*StreamKeyManager, error) {
	keyDerivationTree := NewDefaultTreeKeyRegression(streamMasterKey, 2)
	metadataEncryptionKey, err := keyDerivationTree.GetSeed(1)
	if err != nil {
		return nil, err
	}
	macKey, err := keyDerivationTree.GetSeed(2)
	if err != nil {
		return nil, err
	}
	sharingMasterKey, err := keyDerivationTree.GetSeed(3)
	if err != nil {
		return nil, err
	}
	return &StreamKeyManager{
		treeKeyRegression: NewDefaultTreeKeyRegression(metadataEncryptionKey, numKeysDepth),
		macKey:            macKey,
		sharingMasterKey:  sharingMasterKey,
		isMaster:          true,
	}, nil
}

// NewSharedStreamKeyManager creates the key view of a receiver that was
// granted the given seed nodes and MAC key.
func NewSharedStreamKeyManager(nodes []SeedNode, macKey []byte, numKeysDepth int) *StreamKeyManager {
	return &StreamKeyManager{
		treeKeyRegression: NewSharedTreeKeyRegression(NewAESPRF(), nodes, numKeysDepth, 2),
		macKey:            macKey,
		isMaster:          false,
	}
}

// MacKeyBigInt returns the MAC key as a signed big integer (Java
// BigInteger(byte[]) semantics, as consumed by the HoMAC constructor).
func (s *StreamKeyManager) MacKeyBigInt() *big.Int {
	return bigIntFromSignedBytes(s.macKey)
}

// TreeKeyRegression returns the stream's key-regression tree.
func (s *StreamKeyManager) TreeKeyRegression() *TreeKeyRegression {
	return s.treeKeyRegression
}

// ChunkEncryptionKey derives the AES key for chunk chunkID by combining the
// seeds of chunkID and chunkID+1.
func (s *StreamKeyManager) ChunkEncryptionKey(chunkID int64) ([]byte, error) {
	k1, err := s.treeKeyRegression.GetSeed(chunkID)
	if err != nil {
		return nil, err
	}
	k2, err := s.treeKeyRegression.GetSeed(chunkID + 1)
	if err != nil {
		return nil, err
	}
	return DeriveCombinedKey(s.treeKeyRegression.PRF(), k1, k2), nil
}

// ChunkEncryptionKeyCached is ChunkEncryptionKey with seed caching.
func (s *StreamKeyManager) ChunkEncryptionKeyCached(chunkID int64, keys *CachedKeys) ([]byte, error) {
	if !keys.ContainsKeys() {
		var err error
		if keys.K1, err = s.treeKeyRegression.GetSeed(chunkID); err != nil {
			return nil, err
		}
		if keys.K2, err = s.treeKeyRegression.GetSeed(chunkID + 1); err != nil {
			return nil, err
		}
	}
	return DeriveCombinedKey(s.treeKeyRegression.PRF(), keys.K1, keys.K2), nil
}

// SharingKeyRegression derives a fresh key-regression tree for sharing at the
// given precision level (only the stream master can share).
func (s *StreamKeyManager) SharingKeyRegression(precision int32, depth int) (*TreeKeyRegression, error) {
	if !s.isMaster {
		return nil, errors.New("timecrypt: non-owner is not able to share")
	}
	precisionMasterSecret := s.treeKeyRegression.PRF().ApplyInt(s.sharingMasterKey, precision)
	return NewDefaultTreeKeyRegression(precisionMasterSecret, depth), nil
}

// IsMaster reports whether this manager holds the stream master key.
func (s *StreamKeyManager) IsMaster() bool { return s.isMaster }

// CachedKeys caches the two seeds bracketing a chunk or time range so
// repeated encrypt/decrypt calls skip the tree walk.
// Port of ch.ethz.dsg.timecrypt.crypto.keymanagement.CachedKeys.
type CachedKeys struct {
	K1, K2 []byte
}

// ContainsKeys reports whether both seeds are populated.
func (c *CachedKeys) ContainsKeys() bool { return c.K1 != nil && c.K2 != nil }
