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

package v1

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	hindex "github.com/etclab/hermes/index"

	"github.com/prometheus/prometheus/tsdb/hermes"
)

// hermesSearchParamPrefix marks the request parameters carrying encrypted search
// queries. A parameter named "hermes_q0" binds the query id "q0", which a
// selector then refers to as {__hermes__="q0"}.
const hermesSearchParamPrefix = "hermes_"

// atp: why need this authoritative clock?
// hermesEpochStatus is the response of the epoch endpoint. Writers stamp their
// updates with the encoding, so the engine's clock stays authoritative.
type hermesEpochStatus struct {
	Epoch       string `json:"epoch"`
	EpochNumber uint64 `json:"epochNumber"`
	// p8s server knows how many writers there are in total
	NumWriters int `json:"numWriters"`
}

// hermesEpoch serves the encrypted index's current epoch, which a writer must
// fetch before it can encrypt an update.
func (api *API) hermesEpoch(*http.Request) apiFuncResult {
	if api.hermesIndex == nil {
		return apiFuncResult{nil, &apiError{errorNotFound, hermes.ErrNotEnabled}, nil, nil}
	}
	enc, num := api.hermesIndex.Epoch()
	return apiFuncResult{hermesEpochStatus{
		Epoch:       enc,
		EpochNumber: num,
		NumWriters:  api.hermesIndex.NumWriters(),
	}, nil, nil, nil}
}

// hermesUpdate ingests one writer's encrypted insertion into the index. The body
// is a marshalled Hermes update request; the server can neither read the label
// pair it indexes nor the series id it points at.
func (api *API) hermesUpdate(r *http.Request) apiFuncResult {
	if api.hermesIndex == nil {
		return apiFuncResult{nil, &apiError{errorNotFound, hermes.ErrNotEnabled}, nil, nil}
	}
	blob, err := io.ReadAll(r.Body)
	if err != nil {
		return apiFuncResult{nil, &apiError{errorBadData, fmt.Errorf("reading update body: %w", err)}, nil, nil}
	}
	wid, op, err := hermes.DecodeUpdate(blob)
	if err != nil {
		return apiFuncResult{nil, &apiError{errorBadData, err}, nil, nil}
	}
	if err := api.hermesIndex.Update(wid, op); err != nil {
		return apiFuncResult{nil, &apiError{errorBadData, err}, nil, nil}
	}
	return apiFuncResult{nil, nil, nil, nil}
}

// hermesBindings decodes the encrypted search queries attached to a request and
// pairs them with the index, ready to be carried through the query path in the
// request context. It returns nil when the request carries no encrypted search,
// leaving such requests on the ordinary plaintext path.
//
// The caller must already have parsed the request form.
func (api *API) hermesBindings(r *http.Request) (*hermes.Bindings, error) {
	var queries map[string]*hindex.SearchQuery
	for name, values := range r.Form {
		id, ok := strings.CutPrefix(name, hermesSearchParamPrefix)
		if !ok || id == "" {
			continue
		}
		if len(values) != 1 {
			return nil, fmt.Errorf("hermes: search query %q given %d times, want once", id, len(values))
		}
		q, err := hermes.DecodeSearchQuery(values[0])
		if err != nil {
			return nil, err
		}
		if queries == nil {
			queries = map[string]*hindex.SearchQuery{}
		}
		queries[id] = q
	}
	if queries == nil {
		return nil, nil
	}
	if api.hermesIndex == nil {
		return nil, hermes.ErrNotEnabled
	}
	return hermes.NewBindings(api.hermesIndex, queries), nil
}

// hermesErrorType classifies a binding failure: a disabled index is a 404, so a
// client can tell "not enabled" from a malformed request.
func hermesErrorType(err error) errorType {
	if errors.Is(err, hermes.ErrNotEnabled) {
		return errorNotFound
	}
	return errorBadData
}
