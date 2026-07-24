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

// Package hermes wires the Hermes multi-writer encrypted database
// (github.com/etclab/hermes, IEEE S&P 2025) into Prometheus as an encrypted
// inverted index, replacing the plaintext (label, value) -> series lookup on the
// query path.
//
// Roles, mapped onto the Prometheus deployment:
//
//	Hermes concept   Prometheus concept
//	--------------   ------------------
//	writer class     a scrape target, which holds its own writer key
//	keyword          a canonical (label name, value) pair
//	document id      an opaque, writer-assigned series id ("sid")
//	engine           this package, running inside the untrusted Prometheus
//	reader           the external, key-holding rule evaluator
//
// A scrape target encrypts each of its series' label pairs under its own key and
// submits the resulting update operations here; it exposes the series itself
// carrying nothing but its sid, so Prometheus's own index never sees a real
// label pair. At query time the trusted reader extracts an aggregate key over a
// writer subset and sends it alongside the PromQL selector; the engine matches
// it against the encrypted index and returns sids, which the ordinary postings
// index resolves to series references.
//
// Prometheus therefore learns neither the label pairs that were indexed nor the
// pair a query is searching for — only the access pattern of which writers a
// query matched in.
//
// Deliberate prototype limitations:
//   - The encrypted index is in-memory only; it is not written to the WAL and
//     does not survive a restart, so the scrape targets must be restarted with
//     Prometheus so they re-index.
//   - The engine derives the whole HICKAE authority from the shared demo seed,
//     so it holds key material a real untrusted server must not have. Only
//     Authority.Corr (which is public) is actually used.
package hermes

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/etclab/hermes/detrand"
	"github.com/etclab/hermes/hickae"
	hindex "github.com/etclab/hermes/index"
	"github.com/etclab/hermes/partition"
)

const (
	// MatcherName is the reserved label name through which a PromQL selector
	// carries encrypted searches. Its value is a comma-separated list of query
	// ids, each naming a search query sent alongside the request; the postings
	// for the ids are intersected, so `{__hermes__="q0,q1"}` is the encrypted
	// equivalent of matching on two label pairs at once.
	MatcherName = "__hermes__"

	// SIDLabel is the label carrying a series' opaque, writer-assigned id. It is
	// the only label a scrape target exposes for an encrypted series, and it is
	// what a Hermes document id resolves to.
	SIDLabel = "sid"
)

// ErrNotEnabled is returned when an encrypted search is requested but Prometheus
// was started without the Hermes index.
var ErrNotEnabled = errors.New("hermes: encrypted index is not enabled")

// Index is the server side of the encrypted inverted index: the Hermes engine
// plus the encrypted state written to it. It is safe for concurrent use.
type Index struct {
	eng        *hindex.Engine
	numWriters int
}

// New builds an empty encrypted index for numWriters writer classes, deriving
// the HICKAE authority from the shared demo seed.
//
// Deriving the authority from a seed is the prototype's key-distribution
// shortcut: it lets the writers, the reader and this engine agree on key
// material without a distribution channel. It also means this engine can derive
// secrets it has no business holding — see the package comment.
func New(seed []byte, numWriters int) (*Index, error) {
	if numWriters <= 0 {
		return nil, fmt.Errorf("hermes: need at least one writer class, got %d", numWriters)
	}
	auth, err := hickae.NewAuthority(detrand.New(string(seed)), numWriters)
	if err != nil {
		return nil, fmt.Errorf("hermes: deriving authority: %w", err)
	}
	return &Index{
		eng:        hindex.NewEngine(auth.Corr, partition.DefaultConfig(), numWriters),
		numWriters: numWriters,
	}, nil
}

// NumWriters returns the number of writer classes this index was built for.
func (ix *Index) NumWriters() int { return ix.numWriters }

// Epoch returns the engine's current epoch encoding and number. The engine owns
// the authoritative clock; writers must stamp their updates with the encoding
// returned here so their write cover stays searchable.
func (ix *Index) Epoch() (string, uint64) {
	return ix.eng.CurrentEpoch(), ix.eng.EpochNumber()
}

// Update applies one writer's encrypted insertion to the index.
func (ix *Index) Update(wid int, op *hindex.UpdateOp) error {
	return ix.eng.Update(wid, op)
}

// Search answers an encrypted keyword query and returns the matching sids as
// label values, deduplicated and sorted. Results from every writer in the
// query's subset are unioned: two writers indexing the same label pair produce
// unlinkable index state, so reassembling them is the reader's job and is done
// here on its behalf.
func (ix *Index) Search(q *hindex.SearchQuery) ([]string, error) {
	res, err := ix.eng.Search(q)
	if err != nil {
		return nil, fmt.Errorf("hermes: search: %w", err)
	}
	var sids []string
	for _, r := range res {
		for _, docID := range r.DocIDs {
			sids = append(sids, FormatSID(docID))
		}
	}
	slices.Sort(sids)
	return slices.Compact(sids), nil
}

// FormatSID renders a Hermes document id as the value of the sid label: 16
// lower-case hex digits, so it sorts and compares as a fixed-width string.
func FormatSID(docID uint64) string {
	var b [8]byte
	for i := range b {
		b[i] = byte(docID >> (56 - 8*i))
	}
	return hex.EncodeToString(b[:])
}

// ParseSID is the inverse of FormatSID.
func ParseSID(s string) (uint64, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 8 {
		return 0, fmt.Errorf("hermes: malformed sid %q", s)
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// Bindings couples the index with the encrypted search queries of a single
// request. It travels through the query path in the request context so the
// engine does not have to be threaded through the IndexReader interface, which
// every block reader and test mock would otherwise have to implement.
type Bindings struct {
	ix      *Index
	queries map[string]*hindex.SearchQuery
}

// NewBindings pairs an index with the queries decoded from one request, keyed by
// the ids a __hermes__ matcher refers to.
func NewBindings(ix *Index, queries map[string]*hindex.SearchQuery) *Bindings {
	return &Bindings{ix: ix, queries: queries}
}

type contextKey struct{}

// Bind returns a context carrying b, for the query path to pick up.
func Bind(ctx context.Context, b *Bindings) context.Context {
	return context.WithValue(ctx, contextKey{}, b)
}

// FromContext returns the bindings attached to ctx, if any. Requests that carry
// no encrypted search leave the query path untouched.
func FromContext(ctx context.Context) (*Bindings, bool) {
	b, ok := ctx.Value(contextKey{}).(*Bindings)
	return b, ok && b != nil
}

// Resolve runs the searches named by a __hermes__ matcher value (a
// comma-separated list of query ids) and returns one set of sids per id, in the
// order the ids were given. Each set is meant to be intersected with the others,
// mirroring how matching several label pairs intersects their postings.
func (b *Bindings) Resolve(ids string) ([][]string, error) {
	if b.ix == nil {
		return nil, ErrNotEnabled
	}
	out := make([][]string, 0, strings.Count(ids, ",")+1)
	for id := range strings.SplitSeq(ids, ",") {
		id = strings.TrimSpace(id)
		q, ok := b.queries[id]
		if !ok {
			return nil, fmt.Errorf("hermes: no search query bound for id %q", id)
		}
		sids, err := b.ix.Search(q)
		if err != nil {
			return nil, err
		}
		out = append(out, sids)
	}
	if len(out) == 0 {
		return nil, errors.New("hermes: empty query id list")
	}
	return out, nil
}
