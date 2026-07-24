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

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/prometheus/prometheus/tsdb/hermes"
)

// hermesSeedFile is the name of the shared seed inside the keys directory. The
// scrape targets and the rule evaluator read the same file to derive matching
// key material.
const hermesSeedFile = "hermes.seed"

// hermesOptions are the command-line settings of the encrypted inverted index.
type hermesOptions struct {
	enabled    bool
	keysDir    string
	numWriters int
}

// buildHermesIndex builds the encrypted inverted index from the shared seed, or
// returns nil when the index is disabled.
func buildHermesIndex(o hermesOptions) (*hermes.Index, error) {
	if !o.enabled {
		return nil, nil
	}
	path := filepath.Join(o.keysDir, hermesSeedFile)
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading Hermes seed %s: %w (did you run keytool?)", path, err)
	}
	return hermes.New(seed, o.numWriters)
}
