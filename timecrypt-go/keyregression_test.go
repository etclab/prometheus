package timecrypt

import (
	"bytes"
	"errors"
	"testing"
)

// Ports of timecrypt-crypto/src/test/java/TestTreeKeyRegression.java.

func TestRevealSeedsSharedTreeDerivesSameKeys(t *testing.T) {
	const (
		depth = 20
		from  = 2000
		to    = 3000
	)
	prf := NewAESPRF()
	reg := NewTreeKeyRegression(prf, make([]byte, 16), depth, 2)
	nodes, err := reg.RevealSeeds(from, to)
	if err != nil {
		t.Fatal(err)
	}
	reg2 := NewSharedTreeKeyRegression(prf, nodes, depth, 2)
	for i := int64(from); i <= to; i++ {
		want, err := reg.GetSeed(i)
		if err != nil {
			t.Fatal(err)
		}
		got, err := reg2.GetSeed(i)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("seed %d differs between owner and receiver", i)
		}
	}
}

func TestRevealSeedsInvalidAccess(t *testing.T) {
	const (
		depth = 10
		from  = 100
		to    = 200
	)
	prf := NewAESPRF()
	reg := NewTreeKeyRegression(prf, make([]byte, 16), depth, 2)
	nodes, err := reg.RevealSeeds(from, to)
	if err != nil {
		t.Fatal(err)
	}
	reg2 := NewSharedTreeKeyRegression(prf, nodes, depth, 2)
	if _, err := reg2.GetSeed(99); !errors.Is(err, ErrInvalidKeyDerivation) {
		t.Fatalf("got err=%v, want ErrInvalidKeyDerivation", err)
	}
	if _, err := reg2.GetSeed(150); err != nil {
		t.Fatalf("seed inside the shared range failed: %v", err)
	}
}

func TestSharedStreamKeyManagerDerivesSameChunkKeys(t *testing.T) {
	master := make([]byte, 16)
	master[0] = 42
	owner, err := NewStreamKeyManager(master, 20)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := owner.TreeKeyRegression().RevealSeeds(100, 201)
	if err != nil {
		t.Fatal(err)
	}
	receiver := NewSharedStreamKeyManager(nodes, nil, 20)
	for chunk := int64(100); chunk <= 200; chunk++ {
		want, err := owner.ChunkEncryptionKey(chunk)
		if err != nil {
			t.Fatal(err)
		}
		got, err := receiver.ChunkEncryptionKey(chunk)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("chunk key %d differs between owner and receiver", chunk)
		}
	}
}
