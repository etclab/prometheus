package clusion

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// separator is the literal delimiter Clusion uses to join packed identifiers in
// the response-hiding schemes. The spelling ("seperator") matches the Java
// source so the encoding stays faithful.
const separator = "seperator"

// Lookup is a keyword -> identifiers multi-map (the plaintext index). In the
// Prometheus experiment a keyword is a label pair "name=value" and an
// identifier is a series reference.
type Lookup map[string][]string

// sortedKeys returns the keyword set in deterministic order. Java shards
// keywords across threads in arbitrary order; sorting here keeps builds
// reproducible without changing the resulting structure.
func sortedKeys(l Lookup) []string {
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// javaListString renders items the way Java's AbstractCollection.toString does:
// "[a, b, c]" (and "[]" for the empty list). RR2Lev relies on this exact format.
func javaListString(items []string) string {
	return "[" + strings.Join(items, ", ") + "]"
}

// javaSplit mirrors Java String.split(literal): it splits on sep and discards
// trailing empty fields (which is how padding tokens vanish on search).
func javaSplit(s, sep string) []string {
	parts := strings.Split(s, sep)
	end := len(parts)
	for end > 0 && parts[end-1] == "" {
		end--
	}
	return parts[:end]
}

// stripWhitespace removes all whitespace, mirroring Java replaceAll("\\s", "").
func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// leadingInt parses the leading run of decimal digits of s (Clusion stores array
// slot indices followed by non-digit markers like "***"). It returns the value
// and the number of digits consumed.
func leadingInt(s string) (val, n int) {
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	if n == 0 {
		return 0, 0
	}
	v, _ := strconv.Atoi(s[:n])
	return v, n
}

// takeFreeSlot picks an index into free using Clusion's biased selection
// (getIntFromByte over ceil(log2|free|) bits), removes it, and returns the slot
// value stored there. A guard avoids the infinite loop the Java code can hit
// when free shrinks to one element; the chosen distribution does not affect
// correctness because the slot value is recorded in the encrypted structure.
func takeFreeSlot(free *[]int) int {
	f := *free
	n := len(f)
	if n == 0 {
		panic("clusion: ran out of array slots; increase dataSize")
	}
	position := 0
	if n > 1 {
		bits := int(math.Ceil(math.Log(float64(n)) / math.Log(2)))
		nbytes := int(math.Ceil(math.Log(float64(n)) / (math.Log(2) * 8)))
		if nbytes < 1 {
			nbytes = 1
		}
		position = getIntFromByte(RandomBytes(nbytes), bits)
		for position >= n-1 {
			if position == 0 {
				break
			}
			position /= 2
		}
		if position >= n {
			position = n - 1
		}
	}
	slot := f[position]
	*free = append(f[:position], f[position+1:]...)
	return slot
}

// padBlock returns ids[start:end] padded with pad up to length blockLen.
func padBlock(ids []string, start, blockLen int, pad string) []string {
	end := start + blockLen
	if end > len(ids) {
		end = len(ids)
	}
	block := make([]string, 0, blockLen)
	block = append(block, ids[start:end]...)
	for len(block) < blockLen {
		block = append(block, pad)
	}
	return block
}
