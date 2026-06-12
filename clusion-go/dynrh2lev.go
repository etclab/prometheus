package clusion

import "strconv"

// DynRH2Lev is the dynamic, add-only forward-secure variant of 2Lev (Java
// DynRH2Lev, a variant of Cash et al. NDSS'14). It embeds a static RH2Lev base
// and layers an "updates" dictionary on top: new (keyword, id) pairs are added
// incrementally via TokenUpdate/Update, and Query merges base hits with the
// incremental ones. Delete is intentionally not supported (add-only scope).
type DynRH2Lev struct {
	*RH2Lev
	dictionaryUpdates map[string][]byte // label -> encrypted id
	state             map[string]int    // keyword -> number of additions so far
}

// DictionaryUpdates exposes the incremental updates dictionary.
func (d *DynRH2Lev) DictionaryUpdates() map[string][]byte { return d.dictionaryUpdates }

// ConstructDynRH2Lev builds the static base from lookup (which may be empty) and
// an empty updates dictionary. Mirrors DynRH2Lev.constructEMMParGMM.
func ConstructDynRH2Lev(key []byte, lookup Lookup, bigBlock, smallBlock, dataSize int) (*DynRH2Lev, error) {
	base, err := ConstructRH2Lev(key, lookup, bigBlock, smallBlock, dataSize)
	if err != nil {
		return nil, err
	}
	return &DynRH2Lev{
		RH2Lev:            base,
		dictionaryUpdates: make(map[string][]byte),
		state:             make(map[string]int),
	}, nil
}

// TokenUpdate produces update tokens (label -> encrypted id) for every pair in
// lookup and advances the per-keyword counters. Mirrors DynRH2Lev.tokenUpdate.
// Apply the result with Update. The returned map can be shipped to the server.
func (d *DynRH2Lev) TokenUpdate(key []byte, lookup Lookup) (map[string][]byte, error) {
	tokenUp := make(map[string][]byte)
	key3 := GenerateCmac(key, "3")
	for _, word := range sortedKeys(lookup) {
		key4 := GenerateCmac(key, "4"+word)
		for _, id := range lookup[word] {
			counter := d.state[word]
			d.state[word] = counter + 1
			l := GenerateCmac(key4, strconv.Itoa(counter))
			iv := RandomBytes(ivSize)
			v, err := EncryptAESCTRString(key3, iv, id, d.idSize)
			if err != nil {
				return nil, err
			}
			tokenUp[string(l)] = v
		}
	}
	return tokenUp, nil
}

// Update applies update tokens to the updates dictionary
// (DynRH2Lev.update). Typically called server-side.
func (d *DynRH2Lev) Update(tokenUp map[string][]byte) {
	for label, value := range tokenUp {
		d.dictionaryUpdates[label] = value
	}
}

// DynRH2LevToken is the search token: the static RH2Lev tags plus the update key
// and the current counter for the keyword.
type DynRH2LevToken struct {
	tag1, tag2, updKey []byte
	count              int
}

// GenToken derives the search token for word (DynRH2Lev.genToken). It reads the
// current counter state, so search sees every addition made before this call.
func (d *DynRH2Lev) GenToken(key []byte, word string) DynRH2LevToken {
	return DynRH2LevToken{
		tag1:   GenerateCmac(key, "1"+word),
		tag2:   GenerateCmac(key, "2"+word),
		updKey: GenerateCmac(key, "4"+word),
		count:  d.state[word],
	}
}

// Query returns the matching identifier ciphertexts from both the static base
// and the incremental updates. Decrypt them with Resolve using
// GenerateCmac(masterKey, "3"). Mirrors DynRH2Lev.query.
func (d *DynRH2Lev) Query(token DynRH2LevToken) ([]string, error) {
	result, err := d.RH2Lev.Query(RH2LevToken{token.tag1, token.tag2})
	if err != nil {
		return nil, err
	}
	for i := 0; i < token.count; i++ {
		label := string(GenerateCmac(token.updKey, strconv.Itoa(i)))
		if v, ok := d.dictionaryUpdates[label]; ok {
			result = append(result, string(v))
		}
	}
	return result, nil
}
