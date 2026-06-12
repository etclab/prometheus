package timecrypt

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
)

// ErrInvalidKeyDerivation is returned when a key outside the tree's (or the
// shared subtree's) interval is requested.
// Port of ch.ethz.dsg.timecrypt.crypto.keyRegression.InvalidKeyDerivation.
var ErrInvalidKeyDerivation = errors.New("timecrypt: tree does not support this access")

// KeyRegression derives per-time-step seeds and keys.
// Port of ch.ethz.dsg.timecrypt.crypto.keyRegression.IKeyRegression.
type KeyRegression interface {
	GetKey(id int64, keyBits int) (*big.Int, error)
	GetSeed(id int64) ([]byte, error)
	GetSeeds(from, to int64) ([][]byte, error)
	GetKeys(from, to int64, keyBits int) ([]*big.Int, error)
	PRF() PRF
}

// SeedNode is a (seed, depth, nodeNr) triple in a TreeKeyRegression. NodeNr
// starts from 0 at each depth and increases left to right.
// Port of TreeKeyRegressionNode.
type SeedNode struct {
	Seed   []byte
	Depth  int
	NodeNr int64
}

// TreeKeyRegression derives keys as the leaves of a PRF tree: child i of a
// node with seed s has seed PRF(s, i). An owner holds the root seed and can
// derive every key; a receiver holds only the seed nodes revealed to it and
// can derive exactly the leaves below them.
// Port of ch.ethz.dsg.timecrypt.crypto.keyRegression.TreeKeyRegression.
type TreeKeyRegression struct {
	prf           PRF
	relevantSeeds []SeedNode
	rootSeed      []byte // only set for the owner
	isOwner       bool
	depth         int
	kFactor       int
	powers        []int64
	keyInterval   [2]int64
}

// NewTreeKeyRegression creates an owner tree from a root seed. depth 0 means
// 1 key, depth d means kFactor^d keys.
func NewTreeKeyRegression(prf PRF, rootSeed []byte, depth, kFactor int) *TreeKeyRegression {
	return newTreeKeyRegression(true, prf, []SeedNode{{Seed: rootSeed, Depth: 0, NodeNr: 0}}, depth, kFactor)
}

// NewDefaultTreeKeyRegression creates an owner tree with the default PRF and
// branching factor 2.
func NewDefaultTreeKeyRegression(rootSeed []byte, depth int) *TreeKeyRegression {
	return NewTreeKeyRegression(NewAESPRF(), rootSeed, depth, 2)
}

// NewSharedTreeKeyRegression creates a receiver tree from the seed nodes an
// owner revealed (see RevealSeeds). The receiver can derive exactly the keys
// below those nodes.
func NewSharedTreeKeyRegression(prf PRF, nodes []SeedNode, depth, kFactor int) *TreeKeyRegression {
	return newTreeKeyRegression(false, prf, nodes, depth, kFactor)
}

func newTreeKeyRegression(isOwner bool, prf PRF, relevantSeeds []SeedNode, depth, kFactor int) *TreeKeyRegression {
	if kFactor == 0 {
		panic("timecrypt: kFactor is not allowed to be zero")
	}
	t := &TreeKeyRegression{
		prf:           prf,
		relevantSeeds: relevantSeeds,
		isOwner:       isOwner,
		depth:         depth,
		kFactor:       kFactor,
	}
	if isOwner {
		t.rootSeed = relevantSeeds[0].Seed
	}
	t.computePowers()
	t.keyInterval[0] = t.nodeKeyInterval(relevantSeeds[0])[0]
	t.keyInterval[1] = t.nodeKeyInterval(relevantSeeds[len(relevantSeeds)-1])[1]
	return t
}

func (t *TreeKeyRegression) computePowers() {
	t.powers = make([]int64, t.depth+1)
	cur := int64(1)
	for i := len(t.powers) - 1; i >= 0; i-- {
		t.powers[i] = cur
		cur *= int64(t.kFactor)
	}
}

func (t *TreeKeyRegression) checkValidAccess(id int64) error {
	if t.keyInterval[0] > id || id > t.keyInterval[1] {
		return ErrInvalidKeyDerivation
	}
	return nil
}

// nodeKeyInterval returns the inclusive [from, to] interval of leaf keys
// derivable from node.
func (t *TreeKeyRegression) nodeKeyInterval(node SeedNode) [2]int64 {
	from := node.NodeNr * t.powers[node.Depth]
	return [2]int64{from, from + t.powers[node.Depth] - 1}
}

// relevantNode finds the seed node needed to compute key keyNr.
func (t *TreeKeyRegression) relevantNode(keyNr int64) SeedNode {
	keyID := keyNr - t.keyInterval[0]
	for _, node := range t.relevantSeeds {
		amount := t.powers[node.Depth]
		if keyID < amount {
			return node
		}
		keyID -= amount
	}
	return t.relevantSeeds[0]
}

// computePath returns the PRF child indices from a node at the given depth
// down to the leaf keyID.
func (t *TreeKeyRegression) computePath(depth int, keyID int64) []int32 {
	path := make([]int32, t.depth-depth)
	curID := keyID
	for d := t.depth; d > depth; d-- {
		path[d-depth-1] = int32(curID % int64(t.kFactor))
		curID /= int64(t.kFactor)
	}
	return path
}

// computePathFromRoot returns the PRF child indices from the root to the node
// (depth, nodeNr).
func (t *TreeKeyRegression) computePathFromRoot(depth int, nodeNr int64) []int32 {
	path := make([]int32, depth)
	curID := nodeNr
	for d := depth; d > 0; d-- {
		path[d-1] = int32(curID % int64(t.kFactor))
		curID /= int64(t.kFactor)
	}
	return path
}

// nodeSeeds expands node down to the leaf seeds for keys [from, to].
func (t *TreeKeyRegression) nodeSeeds(node SeedNode, from, to int64) [][]byte {
	pathFrom := t.computePath(node.Depth, from)
	pathTo := t.computePath(node.Depth, to)

	previous := [][]byte{node.Seed}
	for i := 0; i < t.depth-node.Depth; i++ {
		next := make([][]byte, 0, len(previous)*t.kFactor)
		for j, seed := range previous {
			fromK := int32(0)
			toK := int32(t.kFactor - 1)
			if j == 0 {
				fromK = pathFrom[i]
			}
			if j == len(previous)-1 {
				toK = pathTo[i]
			}
			for k := fromK; k <= toK; k++ {
				next = append(next, t.prf.ApplyInt(seed, k))
			}
		}
		previous = next
	}
	return previous
}

func (t *TreeKeyRegression) reveal(depth int, nodeNr int64) SeedNode {
	if depth == 0 {
		return SeedNode{Seed: t.rootSeed, Depth: 0, NodeNr: 0}
	}
	path := t.computePathFromRoot(depth, nodeNr)
	return SeedNode{Seed: t.prf.MultiApply(t.rootSeed, path), Depth: depth, NodeNr: nodeNr}
}

// GetSeed returns the leaf seed with the given identifier.
func (t *TreeKeyRegression) GetSeed(id int64) ([]byte, error) {
	if err := t.checkValidAccess(id); err != nil {
		return nil, err
	}
	node := t.relevantNode(id)
	seed := node.Seed
	if node.Depth != t.depth {
		seed = t.prf.MultiApply(seed, t.computePath(node.Depth, id))
	}
	return seed, nil
}

// GetSeeds returns the leaf seeds in the inclusive range [from, to].
func (t *TreeKeyRegression) GetSeeds(from, to int64) ([][]byte, error) {
	if err := t.checkValidAccess(from); err != nil {
		return nil, err
	}
	if err := t.checkValidAccess(to); err != nil {
		return nil, err
	}
	result := make([][]byte, to-from+1)
	curID := int64(0) // how many seeds we already have
	for _, node := range t.relevantSeeds {
		interval := t.nodeKeyInterval(node)
		curFrom, curTo := interval[0], interval[1]
		if from <= curTo && to >= curFrom {
			// Node is relevant for at least one seed.
			curFrom = max(from, curFrom)
			curTo = min(to, curTo)
			seeds := t.nodeSeeds(node, curFrom, curTo)
			copy(result[curID:], seeds)
			curID += curTo - curFrom + 1
		}
	}
	return result, nil
}

// GetKey derives the keyBits-sized key with the given identifier.
func (t *TreeKeyRegression) GetKey(id int64, keyBits int) (*big.Int, error) {
	seed, err := t.GetSeed(id)
	if err != nil {
		return nil, err
	}
	return DeriveKeyDefault(t.prf, seed, keyBits), nil
}

// GetKeys derives the keyBits-sized keys in the inclusive range [from, to].
func (t *TreeKeyRegression) GetKeys(from, to int64, keyBits int) ([]*big.Int, error) {
	seeds, err := t.GetSeeds(from, to)
	if err != nil {
		return nil, err
	}
	result := make([]*big.Int, len(seeds))
	for i, seed := range seeds {
		result[i] = DeriveKeyDefault(t.prf, seed, keyBits)
	}
	return result, nil
}

// PRF returns the tree's PRF.
func (t *TreeKeyRegression) PRF() PRF { return t.prf }

// RevealSeeds returns the minimal set of seed nodes that allows a receiver to
// derive exactly the keys in [from, to] (TimeCrypt's sharing/view primitive).
// Only the owner can reveal.
func (t *TreeKeyRegression) RevealSeeds(from, to int64) ([]SeedNode, error) {
	if !t.isOwner || t.rootSeed == nil {
		return nil, errors.New("timecrypt: non-owner cannot reveal seeds")
	}
	if from > to {
		return nil, fmt.Errorf("timecrypt: %d is not smaller than %d", from, to)
	}
	var nodes []SeedNode
	add := func(n SeedNode) {
		for _, existing := range nodes {
			if existing.Depth == n.Depth && existing.NodeNr == n.NodeNr {
				return
			}
		}
		nodes = append(nodes, n)
	}
	k := int64(t.kFactor)
	for d := t.depth; d >= 0; d-- {
		for i := 0; i < t.kFactor-1; i++ {
			if from == to {
				add(t.reveal(d, from))
			}
			if from%k != 0 {
				add(t.reveal(d, from))
				from++
			}
			if to%k != k-1 {
				add(t.reveal(d, to))
				to--
			}
			if from > to {
				break
			}
		}
		if from > to {
			break
		}
		from /= k
		to /= k
	}
	sort.Slice(nodes, func(i, j int) bool {
		return t.nodeKeyInterval(nodes[i])[0] < t.nodeKeyInterval(nodes[j])[0]
	})
	return nodes, nil
}
