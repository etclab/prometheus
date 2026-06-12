package clusion

import (
	"math"
	"strconv"
	"strings"
)

// rr2levFileIDSize is the fixed character budget per identifier (Java
// RR2Lev.sizeOfFileIdentifer). Identifiers must encode within this many bytes.
const rr2levFileIDSize = 40

// RR2Lev is the static, response-revealing 2Lev encrypted multi-map (Cash et
// al. NDSS'14). On search the server learns the plaintext identifiers, so this
// flavour is the simplest to reason about. Build it with ConstructRR2Lev.
type RR2Lev struct {
	dictionary map[string][][]byte // tag -> packed (small/medium/large) block
	array      [][]byte            // flat array of encrypted big-blocks
	idSize     int
}

// Dictionary exposes the encrypted dictionary (gamma) — the part a server would
// hold alongside Array.
func (e *RR2Lev) Dictionary() map[string][][]byte { return e.dictionary }

// Array exposes the flat array of encrypted big-blocks.
func (e *RR2Lev) Array() [][]byte { return e.array }

// ConstructRR2Lev builds the encrypted multi-map from lookup. bigBlock and
// smallBlock control the two-level packing thresholds; dataSize is the number
// of array slots reserved for big-blocks (must exceed the total block count).
// Mirrors RR2Lev.constructEMMParGMM + setup, run sequentially.
func ConstructRR2Lev(key []byte, lookup Lookup, bigBlock, smallBlock, dataSize int) (*RR2Lev, error) {
	e := &RR2Lev{
		dictionary: make(map[string][][]byte),
		array:      make([][]byte, dataSize),
		idSize:     rr2levFileIDSize,
	}
	free := make([]int, dataSize)
	for i := range free {
		free[i] = i
	}
	for _, word := range sortedKeys(lookup) {
		if err := e.setupWord(key, word, lookup[word], bigBlock, smallBlock, &free); err != nil {
			return nil, err
		}
	}
	return e, nil
}

func (e *RR2Lev) setupWord(key []byte, word string, ids []string, bigBlock, smallBlock int, free *[]int) error {
	key1 := GenerateHmac(key, "1"+word)
	key2 := GenerateHmac(key, "2"+word)

	t := int(math.Ceil(float64(len(ids)) / float64(bigBlock)))

	// Small case: store the whole padded list inline under tag = HMAC(key1,"0").
	if len(ids) <= smallBlock {
		l := GenerateHmac(key1, "0")
		iv := RandomBytes(ivSize)
		v, err := EncryptAESCTRString(key2, iv, "1 "+javaListString(ids), smallBlock*e.idSize)
		if err != nil {
			return err
		}
		e.dictionary[string(l)] = append(e.dictionary[string(l)], v)
		return nil
	}

	// Medium/large: chop into big-blocks placed at random free array slots.
	var listArrayIndex []string
	for j := 0; j < t; j++ {
		block := padBlock(ids, j*bigBlock, bigBlock, "XX")
		slot := takeFreeSlot(free)
		iv := RandomBytes(ivSize)
		v, err := EncryptAESCTRString(key2, iv, javaListString(block), bigBlock*e.idSize)
		if err != nil {
			return err
		}
		e.array[slot] = v
		listArrayIndex = append(listArrayIndex, strconv.Itoa(slot))
	}

	if t <= smallBlock {
		// Medium: the slot-index list fits inline (flag "2").
		l := GenerateHmac(key1, "0")
		iv := RandomBytes(ivSize)
		v, err := EncryptAESCTRString(key2, iv, "2 "+javaListString(listArrayIndex), smallBlock*e.idSize)
		if err != nil {
			return err
		}
		e.dictionary[string(l)] = append(e.dictionary[string(l)], v)
		return nil
	}

	// Large: index list is itself chopped into the array (flag "3").
	tPrime := int(math.Ceil(float64(t) / float64(bigBlock)))
	var listArrayIndexTwo []string
	for l := 0; l < tPrime; l++ {
		block := padBlock(listArrayIndex, l*bigBlock, bigBlock, "XX")
		slot := takeFreeSlot(free)
		iv := RandomBytes(ivSize)
		v, err := EncryptAESCTRString(key2, iv, javaListString(block), bigBlock*e.idSize)
		if err != nil {
			return err
		}
		e.array[slot] = v
		listArrayIndexTwo = append(listArrayIndexTwo, strconv.Itoa(slot))
	}
	l := GenerateHmac(key1, "0")
	iv := RandomBytes(ivSize)
	v, err := EncryptAESCTRString(key2, iv, "3 "+javaListString(listArrayIndexTwo), smallBlock*e.idSize)
	if err != nil {
		return err
	}
	e.dictionary[string(l)] = append(e.dictionary[string(l)], v)
	return nil
}

// RR2LevToken is the search token for a keyword: two derived keys.
type RR2LevToken [2][]byte

// TokenRR2Lev derives the search token for word (RR2Lev.token).
func TokenRR2Lev(key []byte, word string) RR2LevToken {
	return RR2LevToken{GenerateHmac(key, "1"+word), GenerateHmac(key, "2"+word)}
}

// Query searches for the keyword identified by token and returns the matching
// identifiers in plaintext (RR2Lev.query).
func (e *RR2Lev) Query(token RR2LevToken) ([]string, error) {
	l := GenerateHmac(token[0], "0")
	vals := e.dictionary[string(l)]
	if len(vals) == 0 {
		return []string{}, nil
	}
	pt, err := DecryptAESCTRString(vals[0], token[1])
	if err != nil {
		return nil, err
	}
	temp := strings.Split(string(pt), fileIDTerminator)[0]
	temp = stripWhitespace(temp)
	temp = strings.ReplaceAll(temp, "[", ",")
	temp = strings.ReplaceAll(temp, "]", "")
	result := strings.Split(temp, ",")

	switch result[0] {
	case "1":
		return result[1:], nil
	case "2":
		return e.expandLevel(result[1:], token[1])
	case "3":
		first, err := e.expandLevel(result[1:], token[1])
		if err != nil {
			return nil, err
		}
		return e.expandLevel(first, token[1])
	default:
		return []string{}, nil
	}
}

// expandLevel decrypts each referenced array slot and returns the concatenated
// identifiers (stripping "XX" padding), one indirection level of RR2Lev.query.
func (e *RR2Lev) expandLevel(keys []string, decKey []byte) ([]string, error) {
	var out []string
	for _, k := range keys {
		_, n := leadingInt(k)
		if n == 0 {
			continue
		}
		idx, _ := strconv.Atoi(k[:n])
		if idx < 0 || idx >= len(e.array) || e.array[idx] == nil {
			continue
		}
		pt, err := DecryptAESCTRString(e.array[idx], decKey)
		if err != nil {
			return nil, err
		}
		temp := strings.Split(string(pt), fileIDTerminator)[0]
		temp = stripWhitespace(temp)
		temp = strings.ReplaceAll(temp, ",XX", "")
		temp = strings.ReplaceAll(temp, "[", "")
		temp = strings.ReplaceAll(temp, "]", "")
		out = append(out, strings.Split(temp, ",")...)
	}
	return out, nil
}
