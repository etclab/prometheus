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

package tsdb

import (
	"context"
	"fmt"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/tsdb/hermes"
	"github.com/prometheus/prometheus/tsdb/index"
)

// hermesPostings resolves the encrypted searches carried by ms, returning one
// postings list per search plus the matchers that remain to be matched against
// the plaintext index. A selector carrying no hermes.MatcherName matcher is
// returned unchanged, so the query path is inert unless a request explicitly
// asks for an encrypted lookup.
//
// Each encrypted search resolves to a set of opaque series ids, which the
// ordinary postings index turns into series references: the writer that indexed
// the label pair also stamped its series with the matching hermes.SIDLabel, so
// no separate id-to-reference mapping is needed.
func hermesPostings(ctx context.Context, ix IndexReader, ms []*labels.Matcher) ([]index.Postings, []*labels.Matcher, error) {
	carriesSearch := false
	for _, m := range ms {
		if m.Name == hermes.MatcherName {
			carriesSearch = true
			break
		}
	}
	if !carriesSearch {
		return nil, ms, nil
	}

	bindings, ok := hermes.FromContext(ctx)
	if !ok {
		return nil, nil, hermes.ErrNotEnabled
	}

	var its []index.Postings
	rest := make([]*labels.Matcher, 0, len(ms))
	for _, m := range ms {
		if m.Name != hermes.MatcherName {
			rest = append(rest, m)
			continue
		}
		if m.Type != labels.MatchEqual {
			return nil, nil, fmt.Errorf("hermes: %s only supports equality matching, got %s", hermes.MatcherName, m.Type)
		}
		sidSets, err := bindings.Resolve(m.Value)
		if err != nil {
			return nil, nil, err
		}
		for _, sids := range sidSets {
			p, err := ix.Postings(ctx, hermes.SIDLabel, sids...)
			if err != nil {
				return nil, nil, err
			}
			its = append(its, p)
		}
	}
	return its, rest, nil
}
