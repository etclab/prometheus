package timecrypt

// Part 2 of the guided tour (see keyregression_seednode_test.go for part 1 and
// the shared tourRootSeed / tourDepth / tourKFactor / logNode helpers).
//
// This file covers the two operations that make the tree useful for SHARING:
//
//	RevealSeeds(from, to)  -- owner picks the MINIMAL set of SeedNodes that
//	                          covers exactly the keys [from, to], nothing more.
//	GetSeeds / nodeSeeds   -- expand those nodes back down into one leaf seed
//	                          per key.
//
// Run this part with:
//
//	go test -v -run Reveal
//
// Same tiny tree as part 1: depth 3, branching factor 2, leaf keys 0..7.

import (
	"bytes"
	"testing"
)

// logNodes prints a whole slice of SeedNodes with their key coverage.
func logNodes(t *testing.T, tree *TreeKeyRegression, label string, nodes []SeedNode) {
	t.Helper()
	t.Logf("%s (%d node(s)):", label, len(nodes))
	for _, n := range nodes {
		logNode(t, tree, "  ", n)
	}
}

// assertTilesExactly checks that the node intervals, read left to right, cover
// [from, to] with no gap, no overlap, and nothing outside. This is the core
// correctness property of RevealSeeds.
func assertTilesExactly(t *testing.T, tree *TreeKeyRegression, nodes []SeedNode, from, to int64) {
	t.Helper()
	cursor := from
	for _, n := range nodes {
		iv := tree.nodeKeyInterval(n)
		if iv[0] != cursor {
			t.Fatalf("coverage gap/overlap: next node starts at %d, expected %d", iv[0], cursor)
		}
		cursor = iv[1] + 1
	}
	if cursor != to+1 {
		t.Fatalf("nodes cover [%d..%d], wanted [%d..%d]", from, cursor-1, from, to)
	}
}

// TestReveal_WholeTreeIsOneNode: asking for every key returns just the root.
// One seed reproduces the entire tree, so that is all you need to share.
func TestReveal_WholeTreeIsOneNode(t *testing.T) {
	tree := NewTreeKeyRegression(NewAESPRF(), tourRootSeed, tourDepth, tourKFactor)

	nodes, err := tree.RevealSeeds(0, 7) // all 8 leaf keys
	if err != nil {
		t.Fatal(err)
	}
	logNodes(t, tree, "RevealSeeds(0, 7)", nodes)

	if len(nodes) != 1 {
		t.Fatalf("the whole-tree range should collapse to 1 node, got %d", len(nodes))
	}
	if nodes[0].Depth != 0 || nodes[0].NodeNr != 0 {
		t.Fatalf("expected the root node (0,0), got (%d,%d)", nodes[0].Depth, nodes[0].NodeNr)
	}
	assertTilesExactly(t, tree, nodes, 0, 7)
	t.Log("Sharing all keys == sharing the root: 1 node instead of 8 leaf seeds.")
}

// TestReveal_AlignedRangeCollapsesToOneNode: when [from, to] lines up exactly
// with a subtree, RevealSeeds returns that single ancestor node.
func TestReveal_AlignedRangeCollapsesToOneNode(t *testing.T) {
	tree := NewTreeKeyRegression(NewAESPRF(), tourRootSeed, tourDepth, tourKFactor)

	// Keys [0..3] are exactly the left half -> the depth-1 node (1,0).
	leftHalf, err := tree.RevealSeeds(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	logNodes(t, tree, "RevealSeeds(0, 3)", leftHalf)
	if len(leftHalf) != 1 || leftHalf[0].Depth != 1 || leftHalf[0].NodeNr != 0 {
		t.Fatalf("[0..3] should be the single node (1,0), got %+v", leftHalf)
	}

	// Keys [4..5] line up with the depth-2 node (2,2).
	quarter, err := tree.RevealSeeds(4, 5)
	if err != nil {
		t.Fatal(err)
	}
	logNodes(t, tree, "RevealSeeds(4, 5)", quarter)
	if len(quarter) != 1 || quarter[0].Depth != 2 || quarter[0].NodeNr != 2 {
		t.Fatalf("[4..5] should be the single node (2,2), got %+v", quarter)
	}

	t.Log("A range aligned to a subtree boundary needs only that subtree's root node.")
}

// TestReveal_RaggedRangeNeedsBoundaryNodes: a range whose edges fall in the
// middle of subtrees needs small (often single-leaf) nodes at the boundaries
// plus big nodes in the middle. This is the general, interesting case.
func TestReveal_RaggedRangeNeedsBoundaryNodes(t *testing.T) {
	tree := NewTreeKeyRegression(NewAESPRF(), tourRootSeed, tourDepth, tourKFactor)

	// [1..6] cannot be one subtree: it starts one key into the left half and
	// ends one key short of the right half.
	nodes, err := tree.RevealSeeds(1, 6)
	if err != nil {
		t.Fatal(err)
	}
	logNodes(t, tree, "RevealSeeds(1, 6)", nodes)

	// The algorithm peels the ragged edges off at depth 3 (single leaves 1 and
	// 6), then covers the aligned middle [2..5] with two depth-2 nodes. After
	// sorting we expect, left to right:
	//   (3,1) -> key 1      (a single leaf, the left edge)
	//   (2,1) -> keys 2,3   (a 2-key subtree)
	//   (2,2) -> keys 4,5   (a 2-key subtree)
	//   (3,6) -> key 6      (a single leaf, the right edge)
	want := []struct {
		depth  int
		nodeNr int64
	}{{3, 1}, {2, 1}, {2, 2}, {3, 6}}
	if len(nodes) != len(want) {
		t.Fatalf("[1..6] should need %d nodes, got %d", len(want), len(nodes))
	}
	for i, w := range want {
		if nodes[i].Depth != w.depth || nodes[i].NodeNr != w.nodeNr {
			t.Fatalf("node %d = (%d,%d), want (%d,%d)", i, nodes[i].Depth, nodes[i].NodeNr, w.depth, w.nodeNr)
		}
	}
	assertTilesExactly(t, tree, nodes, 1, 6)
	t.Log("Ragged edges -> deep (small) nodes; aligned middle -> shallow (big) nodes.")
	t.Log("Still only 4 nodes to share instead of 6 individual leaf seeds.")
}

// TestReveal_AlwaysTilesRangeExactly sweeps every sub-range of the 8-key tree
// and checks RevealSeeds covers it precisely -- the property that lets a
// receiver derive exactly the shared keys and not one more.
func TestReveal_AlwaysTilesRangeExactly(t *testing.T) {
	tree := NewTreeKeyRegression(NewAESPRF(), tourRootSeed, tourDepth, tourKFactor)

	maxNodes := 0
	var worst [2]int64
	for from := int64(0); from <= 7; from++ {
		for to := from; to <= 7; to++ {
			nodes, err := tree.RevealSeeds(from, to)
			if err != nil {
				t.Fatalf("RevealSeeds(%d,%d): %v", from, to, err)
			}
			assertTilesExactly(t, tree, nodes, from, to)
			if len(nodes) > maxNodes {
				maxNodes, worst = len(nodes), [2]int64{from, to}
			}
		}
	}
	t.Logf("Every one of the 36 sub-ranges tiled exactly.")
	t.Logf("Worst case used %d nodes (range [%d..%d]); a flat list would use up to 8.",
		maxNodes, worst[0], worst[1])
}

// TestReveal_GetSeedsExpandsNodesToLeaves: RevealSeeds gives you compact NODES;
// GetSeeds (via the internal nodeSeeds) expands them back into one seed per
// leaf key. The two views must agree key-for-key.
func TestReveal_GetSeedsExpandsNodesToLeaves(t *testing.T) {
	tree := NewTreeKeyRegression(NewAESPRF(), tourRootSeed, tourDepth, tourKFactor)

	// Bulk-derive seeds for [2..5]...
	bulk, err := tree.GetSeeds(2, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(bulk) != 4 {
		t.Fatalf("GetSeeds(2,5) should return 4 seeds, got %d", len(bulk))
	}
	// ...and confirm each equals the one-at-a-time derivation.
	for i, id := range []int64{2, 3, 4, 5} {
		one, err := tree.GetSeed(id)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(bulk[i], one) {
			t.Fatalf("bulk seed for key %d != single GetSeed(%d)", id, id)
		}
	}
	t.Log("GetSeeds(2,5) == [GetSeed(2), GetSeed(3), GetSeed(4), GetSeed(5)].")

	// Peek one level lower: nodeSeeds takes a SINGLE node and walks it down to
	// the leaf seeds for a key range inside it. Node (1,0) covers [0..3], so
	// expanding it over [0..3] yields exactly those 4 leaf seeds.
	node := tree.reveal(1, 0)
	expanded := tree.nodeSeeds(node, 0, 3)
	if len(expanded) != 4 {
		t.Fatalf("nodeSeeds over [0..3] should yield 4 leaves, got %d", len(expanded))
	}
	for i, id := range []int64{0, 1, 2, 3} {
		one, _ := tree.GetSeed(id)
		if !bytes.Equal(expanded[i], one) {
			t.Fatalf("nodeSeeds leaf %d != GetSeed(%d)", id, id)
		}
	}
	t.Log("nodeSeeds(node(1,0), 0, 3) re-derives the 4 leaf seeds under that node.")
}

// TestReveal_ShareRoundTrip is the end-to-end story: owner reveals a minimal
// node set, ships it, a receiver rebuilds a tree from JUST those nodes and
// derives identical seeds for the shared range -- and is locked out elsewhere.
func TestReveal_ShareRoundTrip(t *testing.T) {
	prf := NewAESPRF()
	owner := NewTreeKeyRegression(prf, tourRootSeed, tourDepth, tourKFactor)

	const from, to = 1, 6
	nodes, err := owner.RevealSeeds(from, to)
	if err != nil {
		t.Fatal(err)
	}
	logNodes(t, owner, "owner reveals for [1..6]", nodes)

	// The receiver gets ONLY those nodes -- not the root seed.
	receiver := NewSharedTreeKeyRegression(prf, nodes, tourDepth, tourKFactor)
	if receiver.isOwner {
		t.Fatal("a shared tree must not be an owner")
	}
	if receiver.rootSeed != nil {
		t.Fatal("a shared tree must not hold the root seed")
	}

	// Inside [1..6] the receiver reproduces the owner's seeds exactly. Under
	// the hood relevantNode() routes each key to the one shared node above it.
	for id := int64(from); id <= to; id++ {
		want, _ := owner.GetSeed(id)
		got, err := receiver.GetSeed(id)
		if err != nil {
			t.Fatalf("receiver should derive shared key %d: %v", id, err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("receiver's seed for key %d disagrees with owner", id)
		}
	}
	t.Log("Receiver reproduces every seed in [1..6] from the revealed nodes alone.")

	// Keys 0 and 7 were never shared -> the receiver's key interval excludes
	// them and access is refused.
	for _, id := range []int64{0, 7} {
		if _, err := receiver.GetSeed(id); err == nil {
			t.Fatalf("receiver must NOT derive un-shared key %d", id)
		}
	}
	t.Logf("Keys 0 and 7 stay private: receiver's interval is [%d..%d].",
		receiver.keyInterval[0], receiver.keyInterval[1])
}
