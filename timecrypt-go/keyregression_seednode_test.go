package timecrypt

// This file is a guided tour of the SeedNode type and the PRF tree it lives
// in. It is written to be READ and to be RUN with `go test -v -run SeedNode`,
// so almost every test logs what it is doing. None of it tests new behaviour;
// it pins down the mental model behind keyregression.go.
//
// Run just this tour:
//
//	go test -v -run SeedNode
//
// The tests deliberately use a tiny tree (depth 3, branching factor 2 -> 8
// leaf keys) so every number is small enough to check by hand, and a fixed,
// non-zero root seed so the hex dumps are reproducible.

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// A fixed 16-byte root seed (AES-128 key size). Using recognisable bytes
// makes the derivation chains easy to follow in the test output.
var tourRootSeed = []byte{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
}

const (
	tourDepth   = 3 // a depth-3 binary tree...
	tourKFactor = 2 // ...with branching factor 2...
	// ...has tourKFactor^tourDepth = 8 leaf keys, numbered 0..7.
)

// logNode prints a SeedNode plus the facts the tree derives FROM that node:
// which depth/position it sits at and which leaf keys live below it.
func logNode(t *testing.T, tree *TreeKeyRegression, label string, n SeedNode) {
	t.Helper()
	iv := tree.nodeKeyInterval(n)
	t.Logf("%-22s seed=%s  depth=%d  nodeNr=%d  -> covers leaf keys [%d..%d] (%d keys)",
		label, hex.EncodeToString(n.Seed), n.Depth, n.NodeNr, iv[0], iv[1], iv[1]-iv[0]+1)
}

// TestSeedNode_WhatItIs introduces the three fields of a SeedNode and the one
// node every tree starts from: the root.
func TestSeedNode_WhatItIs(t *testing.T) {
	// A SeedNode is just a plain struct: a chunk of secret bytes plus its
	// coordinates in the tree. Nothing is hashed or hidden here; it is a
	// label.
	node := SeedNode{
		Seed:   tourRootSeed,
		Depth:  0,
		NodeNr: 0,
	}

	t.Log("A SeedNode = (Seed, Depth, NodeNr):")
	t.Logf("  Seed   = the %d secret bytes that key the PRF at this node", len(node.Seed))
	t.Logf("  Depth  = how many levels below the root this node sits (root here = %d)", node.Depth)
	t.Logf("  NodeNr = position within that depth, left->right from 0 (root here = %d)", node.NodeNr)

	// The owner's tree is built from exactly this one node: the root seed at
	// depth 0, position 0.
	tree := NewTreeKeyRegression(NewAESPRF(), tourRootSeed, tourDepth, tourKFactor)

	if len(tree.relevantSeeds) != 1 {
		t.Fatalf("a fresh owner tree should hold exactly one seed node, got %d", len(tree.relevantSeeds))
	}
	root := tree.relevantSeeds[0]
	if root.Depth != 0 || root.NodeNr != 0 {
		t.Fatalf("root node should be (depth 0, nodeNr 0), got (depth %d, nodeNr %d)", root.Depth, root.NodeNr)
	}
	if !bytes.Equal(root.Seed, tourRootSeed) {
		t.Fatal("the owner's single seed node should BE the root seed")
	}

	logNode(t, tree, "the root SeedNode:", root)
	t.Logf("The owner holds only this one node yet can derive all %d leaf keys,",
		tree.keyInterval[1]-tree.keyInterval[0]+1)
	t.Log("because every other node is reproducible from it via the PRF.")
}

// TestSeedNode_SeedIsAnAES128Key shows the concrete shape of the Seed field.
func TestSeedNode_SeedIsAnAES128Key(t *testing.T) {
	tree := NewTreeKeyRegression(NewAESPRF(), tourRootSeed, tourDepth, tourKFactor)

	// Every seed in the tree is 16 bytes, because the PRF is raw AES-128 and
	// both its key and its output are one 16-byte block. Deriving a child
	// feeds a parent seed in as the AES key and gets a 16-byte block out, so
	// the size never changes as you walk down the tree.
	root := tree.relevantSeeds[0]
	if len(root.Seed) != 16 {
		t.Fatalf("root seed should be 16 bytes (AES-128), got %d", len(root.Seed))
	}

	// Derive a depth-3 leaf seed and confirm it is also 16 bytes.
	leafSeed, err := tree.GetSeed(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(leafSeed) != 16 {
		t.Fatalf("leaf seed should also be 16 bytes, got %d", len(leafSeed))
	}

	t.Logf("root seed (depth 0): %s", hex.EncodeToString(root.Seed))
	t.Logf("leaf seed (key 5):   %s", hex.EncodeToString(leafSeed))
	t.Log("Same length, totally different bytes: the PRF makes a leaf seed look")
	t.Log("unrelated to its ancestors unless you know the seed in between.")
}

// TestSeedNode_DepthControlsGranularity shows what Depth MEANS: a node's depth
// determines how many leaf keys hang below it.
func TestSeedNode_DepthControlsGranularity(t *testing.T) {
	tree := NewTreeKeyRegression(NewAESPRF(), tourRootSeed, tourDepth, tourKFactor)

	// tree.powers[d] is the number of leaf keys reachable from ANY node at
	// depth d. It is kFactor^(treeDepth - d). For our depth-3 binary tree:
	//   depth 0 (root):  2^3 = 8 keys
	//   depth 1:         2^2 = 4 keys
	//   depth 2:         2^1 = 2 keys
	//   depth 3 (leaf):  2^0 = 1 key
	t.Log("powers[d] = how many leaf keys a node at depth d covers:")
	for d := 0; d <= tree.depth; d++ {
		t.Logf("  depth %d -> %d keys per node", d, tree.powers[d])
	}

	want := []int64{8, 4, 2, 1}
	for d, w := range want {
		if tree.powers[d] != w {
			t.Fatalf("powers[%d] = %d, want %d", d, tree.powers[d], w)
		}
	}

	// So the deeper the node, the narrower its reach. A leaf (depth == tree
	// depth) covers exactly one key: itself.
	if tree.powers[tree.depth] != 1 {
		t.Fatal("a node at the tree's full depth must cover exactly one leaf key")
	}
	t.Log("Bigger tree depth => more leaves total (2^depth); deeper node => fewer leaves under it.")
}

// TestSeedNode_NodeNrIsLeftToRightPosition shows what NodeNr MEANS: at a fixed
// depth, NodeNr walks the nodes left to right, and that position maps directly
// onto a contiguous block of leaf keys.
func TestSeedNode_NodeNrIsLeftToRightPosition(t *testing.T) {
	tree := NewTreeKeyRegression(NewAESPRF(), tourRootSeed, tourDepth, tourKFactor)

	// At depth 2 of a depth-3 binary tree there are 4 nodes (nodeNr 0..3),
	// each covering 2 leaf keys. The interval is simply:
	//   from = nodeNr * powers[depth]
	//   to   = from + powers[depth] - 1
	t.Log("Depth-2 nodes, left to right:")
	for nr := int64(0); nr < 4; nr++ {
		node := tree.reveal(2, nr) // owner-only: recompute this node's seed
		logNode(t, tree, "  node", node)

		iv := tree.nodeKeyInterval(node)
		wantFrom := nr * tree.powers[2]
		if iv[0] != wantFrom {
			t.Fatalf("node (2,%d) starts at key %d, want %d", nr, iv[0], wantFrom)
		}
	}

	// The blocks tile the whole key space with no gaps or overlaps: node 0 ->
	// [0,1], node 1 -> [2,3], node 2 -> [4,5], node 3 -> [6,7].
	t.Log("NodeNr 0,1,2,3 tile keys [0,1],[2,3],[4,5],[6,7] -> contiguous, no overlap.")
}

// TestSeedNode_ChildIsPRFOfParent is the heart of the tree: a child seed is
// just PRF(parentSeed, childIndex). Everything else (reveal, GetSeed,
// nodeSeeds) is built on this single rule.
func TestSeedNode_ChildIsPRFOfParent(t *testing.T) {
	prf := NewAESPRF()
	tree := NewTreeKeyRegression(prf, tourRootSeed, tourDepth, tourKFactor)

	// Child i of a node with seed s has seed PRF(s, i). Let's derive the two
	// children of the root BY HAND and check the tree agrees.
	leftChildByHand := prf.ApplyInt(tourRootSeed, 0)  // depth 1, nodeNr 0
	rightChildByHand := prf.ApplyInt(tourRootSeed, 1) // depth 1, nodeNr 1

	leftChild := tree.reveal(1, 0)
	rightChild := tree.reveal(1, 1)

	if !bytes.Equal(leftChild.Seed, leftChildByHand) {
		t.Fatal("tree's left child seed != PRF(root, 0)")
	}
	if !bytes.Equal(rightChild.Seed, rightChildByHand) {
		t.Fatal("tree's right child seed != PRF(root, 1)")
	}

	logNode(t, tree, "root:", tree.relevantSeeds[0])
	logNode(t, tree, "  child 0 = PRF(root,0):", leftChild)
	logNode(t, tree, "  child 1 = PRF(root,1):", rightChild)

	// Going two levels deep is just applying the PRF twice along the path. The
	// leaf for key 5 in a depth-3 binary tree follows child indices 1,0,1
	// (binary 101 == 5). reveal/GetSeed do exactly this chaining for us.
	manualLeaf5 := prf.ApplyInt(prf.ApplyInt(prf.ApplyInt(tourRootSeed, 1), 0), 1)
	leaf5, err := tree.GetSeed(5)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manualLeaf5, leaf5) {
		t.Fatal("leaf seed for key 5 != PRF(PRF(PRF(root,1),0),1)")
	}
	t.Log("Leaf key 5 = binary 101 => follow children 1,0,1 from the root.")
	t.Log("That is why depth d takes d PRF applications to reach a leaf.")
}

// TestSeedNode_OneWayYouCanGoDownNotUp shows the security point of the whole
// design: from a node you can derive every node BELOW it, but nothing above or
// beside it. This is what makes a SeedNode safe to hand to a receiver.
func TestSeedNode_OneWayYouCanGoDownNotUp(t *testing.T) {
	prf := NewAESPRF()
	owner := NewTreeKeyRegression(prf, tourRootSeed, tourDepth, tourKFactor)

	// Reveal exactly the node covering leaf keys [4..5]: depth 2, nodeNr 2.
	shared := owner.reveal(2, 2)
	logNode(t, owner, "revealed to receiver:", shared)

	// Hand ONLY that node to a receiver.
	receiver := NewSharedTreeKeyRegression(prf, []SeedNode{shared}, tourDepth, tourKFactor)

	// The receiver can derive the leaves below the node...
	for _, id := range []int64{4, 5} {
		got, err := receiver.GetSeed(id)
		if err != nil {
			t.Fatalf("receiver should derive key %d below the revealed node: %v", id, err)
		}
		want, _ := owner.GetSeed(id)
		if !bytes.Equal(got, want) {
			t.Fatalf("receiver's key %d seed disagrees with owner", id)
		}
	}
	t.Log("Receiver holding node (2,2) CAN derive keys 4 and 5 (the leaves below it).")

	// ...but cannot reach anything outside [4..5]. The interval check rejects
	// keys to the left (3) and right (6) even though they share ancestors.
	for _, id := range []int64{3, 6} {
		if _, err := receiver.GetSeed(id); err == nil {
			t.Fatalf("receiver must NOT derive key %d (outside the revealed node)", id)
		}
	}
	t.Log("Receiver CANNOT derive keys 3 or 6: the PRF is one-way, so a child")
	t.Log("seed reveals nothing about its parent, siblings, or cousins.")
}
