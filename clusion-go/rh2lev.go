package clusion

import (
	"math"
	"strconv"
	"strings"
)

// rh2levFileIDSize is the fixed character budget per identifier (Java
// RH2Lev.sizeOfFileIdentifer).
const rh2levFileIDSize = 100

// blockHeadroom is extra buffer space added to every packed block to absorb the
// flag byte, the leading/trailing separators, and the terminator that
// EncryptAESCTRString appends — none of which the bare block*packUnit budget
// accounts for.
const blockHeadroom = len(fileIDTerminator) + 1 + 2*len(separator)

// RH2Lev is the static, response-hiding 2Lev encrypted multi-map. Unlike
// RR2Lev, identifiers are themselves encrypted, so Query returns ciphertexts
// that the client turns back into identifiers with Resolve. It is also the base
// structure that DynRH2Lev extends with an updates dictionary.
type RH2Lev struct {
	dictionary map[string][][]byte
	array      [][]byte
	idSize     int
	// packUnit is the byte budget reserved per packed item in a block. Unlike
	// RR2Lev (which packs raw ids), the response-hiding scheme packs encrypted
	// ids, each ivSize+idSize bytes plus the separator. The Java original reuses
	// sizeOfFileIdentifer here, which under-sizes blocks and makes the parallel
	// builder silently drop data for any keyword that overflows a block; we size
	// it correctly instead. See docs/01-PORTING-NOTES.md.
	packUnit int
}

// Dictionary exposes the encrypted dictionary (gamma).
func (e *RH2Lev) Dictionary() map[string][][]byte { return e.dictionary }

// Array exposes the flat array of encrypted big-blocks.
func (e *RH2Lev) Array() [][]byte { return e.array }

// ConstructRH2Lev builds the response-hiding encrypted multi-map from lookup.
// Parameters match ConstructRR2Lev. Mirrors RH2Lev.constructEMMParGMM + setup.
func ConstructRH2Lev(key []byte, lookup Lookup, bigBlock, smallBlock, dataSize int) (*RH2Lev, error) {
	e := &RH2Lev{
		dictionary: make(map[string][][]byte),
		array:      make([][]byte, dataSize),
		idSize:     rh2levFileIDSize,
		packUnit:   ivSize + rh2levFileIDSize + len(separator),
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

func (e *RH2Lev) setupWord(key []byte, word string, ids []string, bigBlock, smallBlock int, free *[]int) error {
	key1 := GenerateCmac(key, "1"+word)
	key2 := GenerateCmac(key, "2"+word)
	key3 := GenerateCmac(key, "3") // SIV-style key shared by all words

	// Encrypt every identifier; keep the raw ciphertext bytes as Go strings
	// (lossless), then join with the separator.
	encryptedID := make([]string, 0, len(ids))
	for _, id := range ids {
		iv := RandomBytes(ivSize)
		ct, err := EncryptAESCTRString(key3, iv, id, e.idSize)
		if err != nil {
			return err
		}
		encryptedID = append(encryptedID, string(ct))
	}

	t := int(math.Ceil(float64(len(ids)) / float64(bigBlock)))

	if len(ids) <= smallBlock {
		l := GenerateCmac(key1, "0")
		iv := RandomBytes(ivSize)
		v, err := EncryptAESCTRString(key2, iv, "1"+separator+joinSep(encryptedID), smallBlock*e.packUnit+blockHeadroom)
		if err != nil {
			return err
		}
		e.dictionary[string(l)] = append(e.dictionary[string(l)], v)
		return nil
	}

	var listArrayIndex []string
	for j := 0; j < t; j++ {
		block := padBlock(encryptedID, j*bigBlock, bigBlock, separator)
		slot := takeFreeSlot(free)
		iv := RandomBytes(ivSize)
		v, err := EncryptAESCTRString(key2, iv, joinSep(block), bigBlock*e.packUnit+blockHeadroom)
		if err != nil {
			return err
		}
		e.array[slot] = v
		listArrayIndex = append(listArrayIndex, strconv.Itoa(slot)+"***")
	}

	if t <= smallBlock {
		l := GenerateCmac(key1, "0")
		iv := RandomBytes(ivSize)
		v, err := EncryptAESCTRString(key2, iv, "2"+separator+joinSep(listArrayIndex), smallBlock*e.packUnit+blockHeadroom)
		if err != nil {
			return err
		}
		e.dictionary[string(l)] = append(e.dictionary[string(l)], v)
		return nil
	}

	tPrime := int(math.Ceil(float64(t) / float64(bigBlock)))
	var listArrayIndexTwo []string
	for l := 0; l < tPrime; l++ {
		block := padBlock(listArrayIndex, l*bigBlock, bigBlock, "***")
		slot := takeFreeSlot(free)
		iv := RandomBytes(ivSize)
		v, err := EncryptAESCTRString(key2, iv, joinSep(block), bigBlock*e.packUnit+blockHeadroom)
		if err != nil {
			return err
		}
		e.array[slot] = v
		listArrayIndexTwo = append(listArrayIndexTwo, strconv.Itoa(slot)+separator)
	}
	l := GenerateCmac(key1, "0")
	iv := RandomBytes(ivSize)
	v, err := EncryptAESCTRString(key2, iv, "3"+separator+joinSep(listArrayIndexTwo), smallBlock*e.packUnit+blockHeadroom)
	if err != nil {
		return err
	}
	e.dictionary[string(l)] = append(e.dictionary[string(l)], v)
	return nil
}

// joinSep concatenates each item followed by the separator (matching the Java
// "s + separator" accumulation, including the trailing separator).
func joinSep(items []string) string {
	var b strings.Builder
	for _, s := range items {
		b.WriteString(s)
		b.WriteString(separator)
	}
	return b.String()
}

// RH2LevToken is the search token for a keyword.
type RH2LevToken [2][]byte

// TokenRH2Lev derives the search token for word (RH2Lev.token).
func TokenRH2Lev(key []byte, word string) RH2LevToken {
	return RH2LevToken{GenerateCmac(key, "1"+word), GenerateCmac(key, "2"+word)}
}

// Query searches for the keyword identified by token and returns the matching
// identifier ciphertexts (still encrypted). Use Resolve to decrypt them.
// Mirrors RH2Lev.query.
func (e *RH2Lev) Query(token RH2LevToken) ([]string, error) {
	l := GenerateCmac(token[0], "0")
	vals := e.dictionary[string(l)]
	if len(vals) == 0 {
		return []string{}, nil
	}
	pt, err := DecryptAESCTRString(vals[0], token[1])
	if err != nil {
		return nil, err
	}
	temp := strings.Split(string(pt), fileIDTerminator)[0]
	result := javaSplit(temp, separator)
	if len(result) == 0 {
		return []string{}, nil
	}

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
// identifier ciphertexts, one indirection level of RH2Lev.query.
func (e *RH2Lev) expandLevel(keys []string, decKey []byte) ([]string, error) {
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
		out = append(out, javaSplit(temp, separator)...)
	}
	return out, nil
}

// Resolve decrypts identifier ciphertexts returned by Query back into the
// original identifiers. key must be GenerateCmac(masterKey, "3"). Mirrors
// RH2Lev.resolve.
func Resolve(key []byte, ciphertexts []string) ([]string, error) {
	out := make([]string, 0, len(ciphertexts))
	for _, c := range ciphertexts {
		pt, err := DecryptAESCTRString([]byte(c), key)
		if err != nil {
			return nil, err
		}
		out = append(out, strings.Split(string(pt), fileIDTerminator)[0])
	}
	return out, nil
}
