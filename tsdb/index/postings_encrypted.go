// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package index

import (
	"context"
	"slices"
	"strconv"
	"sync"

	clusion "github.com/aashutoshpaudyal/clusion-go"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
)

// Parameters for the static RH2Lev base of the encrypted multi-map. The base
// is constructed empty (every posting arrives through the dynamic updates
// dictionary), so these only need to be valid, not tuned.
const (
	encryptedPostingsBigBlock   = 1000
	encryptedPostingsSmallBlock = 100
	encryptedPostingsDataSize   = 10000
)

// EncryptedMemPostings is a searchable-symmetric-encryption (SSE) counterpart
// of MemPostings: an in-memory inverted index from label pairs to series
// references in which both the label pairs (keywords) and the series
// references (identifiers) are stored encrypted, backed by the add-only
// dynamic response-hiding 2Lev scheme (DynRH2Lev) from the Clusion port.
//
// A keyword is a label pair encoded as "name=value" and an identifier is the
// decimal series reference. Add encrypts each (label pair, series ref) into an
// update token — a CMAC-derived dictionary label and an AES-CTR identifier
// ciphertext — via TokenUpdate, so nothing about the pair is stored in the
// clear. Postings derives a search token for the requested pair and resolves
// the matching ciphertexts back into series references.
//
// For simplicity this prototype plays both SSE roles in one process: it holds
// the client master key (token generation) next to the server-side encrypted
// structure. In a real split deployment TokenUpdate/GenToken/Resolve run at
// the client and only the tokens cross to the server.
//
// Compared to MemPostings, the scheme is add-only and supports exact-keyword
// search only: Delete, label-name/value enumeration, and regex matching are
// not possible by design (that is the point of keyword hiding).
type EncryptedMemPostings struct {
	mtx sync.Mutex

	// key is the client master key; resolveKey is GenerateCmac(key, "3"),
	// the shared identifier-decryption key used by Resolve.
	key        []byte
	resolveKey []byte

	// emm is the encrypted multi-map (the "server" state).
	emm *clusion.DynRH2Lev
}

// NewEncryptedMemPostings returns an empty encrypted postings index using the
// given master key. The key must be a valid AES key size (16, 24 or 32 bytes),
// e.g. derived with clusion.KeyGen.
func NewEncryptedMemPostings(key []byte) (*EncryptedMemPostings, error) {
	emm, err := clusion.ConstructDynRH2Lev(key, clusion.Lookup{},
		encryptedPostingsBigBlock, encryptedPostingsSmallBlock, encryptedPostingsDataSize)
	if err != nil {
		return nil, err
	}
	return &EncryptedMemPostings{
		key:        key,
		resolveKey: clusion.GenerateCmac(key, "3"),
		emm:        emm,
	}, nil
}

// encryptedPostingsKeyword encodes a label pair as the SSE keyword. Label
// names cannot contain '=', so the encoding is unambiguous. AllPostingsKey
// encodes to "=", mirroring the special all-postings entry of MemPostings.
func encryptedPostingsKeyword(name, value string) string {
	return name + "=" + value
}

// Add indexes the series with the given ID under each of its label pairs,
// plus the all-postings key. Each pair is encrypted into an update token
// client-side and applied to the encrypted updates dictionary.
func (p *EncryptedMemPostings) Add(id storage.SeriesRef, lset labels.Labels) error {
	idStr := strconv.FormatUint(uint64(id), 10)
	lookup := make(clusion.Lookup, lset.Len()+1)
	lset.Range(func(l labels.Label) {
		w := encryptedPostingsKeyword(l.Name, l.Value)
		lookup[w] = append(lookup[w], idStr)
	})
	lookup[encryptedPostingsKeyword(AllPostingsKey())] = []string{idStr}

	p.mtx.Lock()
	defer p.mtx.Unlock()
	tokenUp, err := p.emm.TokenUpdate(p.key, lookup)
	if err != nil {
		return err
	}
	p.emm.Update(tokenUp)
	return nil
}

// GenToken derives the encrypted search token for a label pair. This is the
// client-side half of a search: the plaintext pair goes in, and only the
// resulting token (CMAC tags plus the current update counter) is handed to
// the server side. The pair itself never touches the encrypted structure.
func (p *EncryptedMemPostings) GenToken(name, value string) clusion.DynRH2LevToken {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	return p.emm.GenToken(p.key, encryptedPostingsKeyword(name, value))
}

// QueryCiphertexts is the server-side half of a search: it matches the token
// against the encrypted multi-map and returns the hit identifier ciphertexts,
// still encrypted. The server learns neither the label pair behind the token
// nor the series references inside the results.
func (p *EncryptedMemPostings) QueryCiphertexts(token clusion.DynRH2LevToken) ([]string, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	return p.emm.Query(token)
}

// ResolveRefs decrypts identifier ciphertexts returned by QueryCiphertexts
// back into series references (client side, needs the resolve key).
func (p *EncryptedMemPostings) ResolveRefs(cts []string) ([]storage.SeriesRef, error) {
	ids, err := clusion.Resolve(p.resolveKey, cts)
	if err != nil {
		return nil, err
	}
	refs := make([]storage.SeriesRef, 0, len(ids))
	for _, id := range ids {
		ref, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			return nil, err
		}
		refs = append(refs, storage.SeriesRef(ref))
	}
	return refs, nil
}

// Postings returns the union of postings for the given label name and values,
// sorted. It bundles the full SSE round trip per pair — GenToken (client),
// QueryCiphertexts (server), ResolveRefs (client) — so it can serve as a
// drop-in for the MemPostings query path. Unknown pairs contribute nothing,
// matching MemPostings semantics.
func (p *EncryptedMemPostings) Postings(_ context.Context, name string, values ...string) Postings {
	var refs []storage.SeriesRef
	for _, value := range values {
		cts, err := p.QueryCiphertexts(p.GenToken(name, value))
		if err != nil {
			return ErrPostings(err)
		}
		valueRefs, err := p.ResolveRefs(cts)
		if err != nil {
			return ErrPostings(err)
		}
		refs = append(refs, valueRefs...)
	}
	slices.Sort(refs)
	refs = slices.Compact(refs)
	return NewListPostings(refs)
}

// All returns the postings list of every indexed series via the all-postings
// keyword.
func (p *EncryptedMemPostings) All(ctx context.Context) Postings {
	name, value := AllPostingsKey()
	return p.Postings(ctx, name, value)
}

// DictionaryUpdates exposes the server-side encrypted updates dictionary
// (CMAC-derived labels to identifier ciphertexts) for inspection in tests and
// experiments. The contents reveal neither label pairs nor series references.
func (p *EncryptedMemPostings) DictionaryUpdates() map[string][]byte {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	return p.emm.DictionaryUpdates()
}
