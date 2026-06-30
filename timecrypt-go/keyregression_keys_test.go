package timecrypt

// Part 3, the final layer of the guided tour (parts 1 and 2 are in
// keyregression_seednode_test.go and keyregression_reveal_test.go).
//
// So far a leaf of the tree has been a SEED -- 16 raw bytes. This file shows
// the last hop: turning a leaf seed into an actual KEY, how different keys are
// derived from the SAME seed without colliding (domain separation), and how
// StreamKeyManager assembles all of this into per-chunk AES keys for a real
// stream.
//
// Run this part with:
//
//	go test -v -run 'Key_|Stream_'

import (
	"bytes"
	"math/big"
	"testing"
)

// A fixed stream master key, distinct from tourRootSeed, so it is obvious in
// the output which value seeds which tree.
var tourStreamMaster = []byte{
	0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
}

// TestKey_SeedBecomesKeyViaPRF shows the seed -> key step. A key is NOT the
// seed; it is one more PRF application with a fixed "default" input, so the
// seed can be kept to derive siblings while the key is the thing you encrypt
// with.
func TestKey_SeedBecomesKeyViaPRF(t *testing.T) {
	prf := NewAESPRF()
	tree := NewTreeKeyRegression(prf, tourRootSeed, tourDepth, tourKFactor)

	// GetKey(id, bits) == DeriveKeyDefault(prf, GetSeed(id), bits).
	seed, err := tree.GetSeed(5)
	if err != nil {
		t.Fatal(err)
	}
	key, err := tree.GetKey(5, 128)
	if err != nil {
		t.Fatal(err)
	}
	viaSeed := DeriveKeyDefault(prf, seed, 128)
	if key.Cmp(viaSeed) != 0 {
		t.Fatal("GetKey != DeriveKeyDefault(GetSeed)")
	}

	// For a 128-bit key from a 128-bit PRF output there is no folding: the key
	// is exactly PRF(seed, 0xFF^16) read as a big integer.
	raw := prf.Apply(seed, defaultKeyDerivationInput())
	if key.Cmp(new(big.Int).SetBytes(raw)) != 0 {
		t.Fatal("128-bit default key should equal the raw PRF output over the all-0xFF input")
	}

	t.Logf("seed for key 5 : %x", seed)
	t.Logf("128-bit key    : %032x", key)
	t.Log("Key = PRF(seed, default-input). The seed stays secret to derive neighbours;")
	t.Log("the key is what HEAC/AES actually uses. Same seed always -> same key.")

	// Determinism: deriving again yields an identical key.
	again, _ := tree.GetKey(5, 128)
	if key.Cmp(again) != 0 {
		t.Fatal("key derivation must be deterministic")
	}
}

// TestKey_BitSizeFoldsTheOutput shows what the `keyBits` argument does: a key
// smaller than the 128-bit PRF output is built by XOR-folding the output into
// that many bits, so every output bit still influences the key.
func TestKey_BitSizeFoldsTheOutput(t *testing.T) {
	prf := NewAESPRF()
	tree := NewTreeKeyRegression(prf, tourRootSeed, tourDepth, tourKFactor)
	seed, _ := tree.GetSeed(2)

	// A 64-bit key folds the 128-bit (16-byte) PRF output into two 8-byte
	// halves XOR'd together.
	full := prf.Apply(seed, defaultKeyDerivationInput()) // 16 bytes
	hi := new(big.Int).SetBytes(full[:8])
	lo := new(big.Int).SetBytes(full[8:])
	wantFolded := new(big.Int).Xor(hi, lo)

	got := DeriveKeyDefault(prf, seed, 64)
	if got.Cmp(wantFolded) != 0 {
		t.Fatal("64-bit key should be the high half XOR the low half of the PRF output")
	}

	t.Logf("PRF output (128b): %032x", full)
	t.Logf("high 64 XOR low 64: %016x", got)
	t.Log("keyBits chooses key size; smaller keys fold the full output so no bit is dropped.")
}

// TestKey_DomainSeparation shows why one seed can safely yield several keys:
// the PRF input differs per purpose, so the encryption key, the MAC key, and
// the default key derived from the SAME seed are unrelated.
func TestKey_DomainSeparation(t *testing.T) {
	prf := NewAESPRF()
	tree := NewTreeKeyRegression(prf, tourRootSeed, tourDepth, tourKFactor)
	seed, _ := tree.GetSeed(3)

	// Three purposes, three different PRF inputs (see keyutil.go):
	//   default : 0xFF^16
	//   enc(id) : 0xFF^8 || id
	//   mac(id) : id || 0xFF^8
	def := DeriveKeyDefault(prf, seed, 128)
	enc := DeriveKeyForID(prf, seed, true, 7, 128)  // encryption key for slot 7
	mac := DeriveKeyForID(prf, seed, false, 7, 128) // MAC key for slot 7

	if def.Cmp(enc) == 0 || def.Cmp(mac) == 0 || enc.Cmp(mac) == 0 {
		t.Fatal("default/enc/mac keys from one seed must all differ (domain separation)")
	}

	// Even the SAME purpose with a different slot id gives a different key.
	encSlot8 := DeriveKeyForID(prf, seed, true, 8, 128)
	if enc.Cmp(encSlot8) == 0 {
		t.Fatal("enc keys for different metadata slots must differ")
	}

	t.Logf("default key  : %032x", def)
	t.Logf("enc key sl7  : %032x", enc)
	t.Logf("mac key sl7  : %032x", mac)
	t.Logf("enc key sl8  : %032x", encSlot8)
	t.Log("One seed, many keys: the PRF input encodes the purpose, so keys never collide.")
}

// TestStream_KeyHierarchy shows how StreamKeyManager turns a single stream
// master key into the three top-level secrets, via its own little depth-2 tree.
func TestStream_KeyHierarchy(t *testing.T) {
	const numKeysDepth = 4 // 2^4 = 16 derivable chunk/metadata keys
	owner, err := NewStreamKeyManager(tourStreamMaster, numKeysDepth)
	if err != nil {
		t.Fatal(err)
	}

	// The master key seeds a depth-2 tree (4 leaves). The manager uses three
	// of them:
	//   leaf 1 -> root seed of the chunk/metadata key-regression tree
	//   leaf 2 -> MAC key
	//   leaf 3 -> sharing master key
	masterTree := NewDefaultTreeKeyRegression(tourStreamMaster, 2)
	leaf1, _ := masterTree.GetSeed(1)
	leaf2, _ := masterTree.GetSeed(2)
	leaf3, _ := masterTree.GetSeed(3)

	if !bytes.Equal(owner.TreeKeyRegression().rootSeed, leaf1) {
		t.Fatal("the chunk tree's root should be master-leaf 1")
	}
	if !bytes.Equal(owner.macKey, leaf2) {
		t.Fatal("the MAC key should be master-leaf 2")
	}
	if !bytes.Equal(owner.sharingMasterKey, leaf3) {
		t.Fatal("the sharing master key should be master-leaf 3")
	}
	if bytes.Equal(leaf1, leaf2) || bytes.Equal(leaf2, leaf3) || bytes.Equal(leaf1, leaf3) {
		t.Fatal("the three top-level secrets must be distinct")
	}

	t.Logf("stream master      : %x", tourStreamMaster)
	t.Logf("  -> chunk-tree root: %x", leaf1)
	t.Logf("  -> MAC key        : %x", leaf2)
	t.Logf("  -> sharing master : %x", leaf3)
	t.Logf("The chunk tree (depth %d) below leaf 1 holds %d chunk seeds.",
		numKeysDepth, int64(1)<<numKeysDepth)
}

// TestStream_ChunkKeyCombinesAdjacentSeeds shows the one twist in chunk keys:
// the key for chunk N is derived from BOTH seed N and seed N+1, so a chunk key
// reveals nothing about either neighbouring seed on its own.
func TestStream_ChunkKeyCombinesAdjacentSeeds(t *testing.T) {
	owner, err := NewStreamKeyManager(tourStreamMaster, 4)
	if err != nil {
		t.Fatal(err)
	}
	tree := owner.TreeKeyRegression()
	prf := tree.PRF()

	// ChunkEncryptionKey(5) == DeriveCombinedKey(seed5, seed6).
	got, err := owner.ChunkEncryptionKey(5)
	if err != nil {
		t.Fatal(err)
	}
	seed5, _ := tree.GetSeed(5)
	seed6, _ := tree.GetSeed(6)
	want := DeriveCombinedKey(prf, seed5, seed6)
	if !bytes.Equal(got, want) {
		t.Fatal("ChunkEncryptionKey(5) should combine seed 5 and seed 6")
	}

	// Adjacent chunk keys share a seed (chunk 5 uses seeds 5,6; chunk 6 uses
	// 6,7) yet the keys themselves are unrelated.
	keyChunk6, _ := owner.ChunkEncryptionKey(6)
	if bytes.Equal(got, keyChunk6) {
		t.Fatal("neighbouring chunk keys must differ")
	}

	t.Logf("seed 5         : %x", seed5)
	t.Logf("seed 6         : %x", seed6)
	t.Logf("chunk-5 AES key: %x  (combines seeds 5 & 6)", got)
	t.Log("Because chunk N needs seeds N and N+1, sharing chunks [a..b] means")
	t.Log("revealing leaf seeds [a..b+1] -- one past the last chunk.")
}

// TestStream_ShareChunksRevealOneExtraSeed is the full real-world flow and the
// payoff of the whole tour: an owner shares a window of chunks by revealing a
// minimal seed set, and a receiver decrypts exactly those chunks.
func TestStream_ShareChunksRevealOneExtraSeed(t *testing.T) {
	const numKeysDepth = 4
	owner, err := NewStreamKeyManager(tourStreamMaster, numKeysDepth)
	if err != nil {
		t.Fatal(err)
	}

	// Share chunks 4..6. Chunk 6 needs seed 7, so reveal seeds [4..7].
	const fromChunk, toChunk = 4, 6
	nodes, err := owner.TreeKeyRegression().RevealSeeds(fromChunk, toChunk+1)
	if err != nil {
		t.Fatal(err)
	}
	logNodes(t, owner.TreeKeyRegression(), "owner reveals chunk seeds [4..7]", nodes)

	// The receiver also needs the MAC key to verify, but NOT the master key.
	receiver := NewSharedStreamKeyManager(nodes, owner.macKey, numKeysDepth)

	for chunk := int64(fromChunk); chunk <= toChunk; chunk++ {
		want, _ := owner.ChunkEncryptionKey(chunk)
		got, err := receiver.ChunkEncryptionKey(chunk)
		if err != nil {
			t.Fatalf("receiver should derive chunk key %d: %v", chunk, err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("chunk key %d differs between owner and receiver", chunk)
		}
	}
	t.Log("Receiver derives identical AES keys for chunks 4, 5 and 6.")

	// It cannot go one chunk further: chunk 7 would need seed 8, which was
	// never revealed.
	if _, err := receiver.ChunkEncryptionKey(7); err == nil {
		t.Fatal("receiver must NOT derive chunk 7 (seed 8 was never revealed)")
	}
	t.Log("Chunk 7 is refused: its seed 8 lies outside the shared set. Access is")
	t.Log("bounded to exactly the granted window -- the whole point of the tree.")

	// Show the under-reveal failure mode too: revealing only [4..6] leaves the
	// LAST chunk underivable, because chunk 6 still needs seed 7.
	tooFew, _ := owner.TreeKeyRegression().RevealSeeds(fromChunk, toChunk)
	shortReceiver := NewSharedStreamKeyManager(tooFew, owner.macKey, numKeysDepth)
	if _, err := shortReceiver.ChunkEncryptionKey(toChunk); err == nil {
		t.Fatal("revealing only [4..6] should leave chunk 6 underivable (needs seed 7)")
	}
	t.Log("Under-revealing (only [4..6]) breaks the last chunk: remember the +1.")
}
