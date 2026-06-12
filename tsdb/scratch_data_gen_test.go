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
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/model/labels"
)

// This file is the configurable data generator for the scratch query-overhead
// benchmarks. Instead of baking the dataset into the benchmark code, a separate
// generator writes the series and their raw sample values to a JSON fixture
// that the Benchmark* functions load. The fixture is reproducible (seeded) and
// inspectable, and its size is configurable from the command line.

// defaultScratchDataPath is where the generated fixture lives by default,
// relative to the tsdb package directory (the test working directory).
const defaultScratchDataPath = "testdata/scratch_benchdata.json"

// Command-line flags shared by the generator and the benchmarks. Change the
// dataset size by regenerating with TestGenerateScratchData; the benchmarks
// then load whatever the fixture contains.
var (
	scratchDataPath  = flag.String("scratch.data", defaultScratchDataPath, "Path to the scratch benchmark data fixture (written by TestGenerateScratchData, read by Benchmark*).")
	scratchNumSeries = flag.Int("scratch.numSeries", 2, "Number of series to generate.")
	scratchSamples   = flag.Int("scratch.samplesPerSeries", 2, "Number of samples per series to generate.")
	scratchSeed      = flag.Int64("scratch.seed", 1, "PRNG seed for reproducible sample values.")
)

// scratchVendors are the vendor label values cycled across the generated
// series; the benchmark selector matches one of them.
var scratchVendors = []string{"intel", "amd", "arm"}

// scratchSelName and scratchSelValue are the label pair the benchmarks query on.
const (
	scratchSelName  = "vendor"
	scratchSelValue = "intel"
)

// scratchSeries is one generated series: its label set and its raw plaintext
// sample values in time order.
type scratchSeries struct {
	Labels map[string]string `json:"labels"`
	Values []float64         `json:"values"`
}

// labelSet rebuilds the labels.Labels of the series.
func (s scratchSeries) labelSet() labels.Labels {
	return labels.FromMap(s.Labels)
}

// matched reports whether the series is selected by the benchmark selector.
func (s scratchSeries) matched() bool {
	return s.Labels[scratchSelName] == scratchSelValue
}

// scratchDataConfig records the parameters a dataset was generated with.
type scratchDataConfig struct {
	NumSeries        int      `json:"numSeries"`
	SamplesPerSeries int      `json:"samplesPerSeries"`
	Vendors          []string `json:"vendors"`
	SelName          string   `json:"selName"`
	SelValue         string   `json:"selValue"`
	Seed             int64    `json:"seed"`
}

// scratchDataset is the full generated fixture: the config plus every series
// with its raw values.
type scratchDataset struct {
	Config scratchDataConfig `json:"config"`
	Series []scratchSeries   `json:"series"`
}

// matchedSeries returns how many series the selector picks out.
func (ds scratchDataset) matchedSeries() int {
	n := 0
	for _, s := range ds.Series {
		if s.matched() {
			n++
		}
	}
	return n
}

// configFromFlags builds a generation config from the current flag values.
func configFromFlags() scratchDataConfig {
	return scratchDataConfig{
		NumSeries:        *scratchNumSeries,
		SamplesPerSeries: *scratchSamples,
		Vendors:          scratchVendors,
		SelName:          scratchSelName,
		SelValue:         scratchSelValue,
		Seed:             *scratchSeed,
	}
}

// generateScratchData builds a deterministic dataset from cfg. Sample values
// are pseudo-random in [0, 1.5) (cpu_usage_ratio-like), seeded for repeatability.
// The vendor label cycles through cfg.Vendors so the selector matches roughly
// one in len(Vendors) series, and os alternates between linux and windows.
func generateScratchData(cfg scratchDataConfig) scratchDataset {
	rng := rand.New(rand.NewSource(cfg.Seed))
	ds := scratchDataset{Config: cfg, Series: make([]scratchSeries, cfg.NumSeries)}
	for i := 0; i < cfg.NumSeries; i++ {
		vendor := cfg.Vendors[i%len(cfg.Vendors)]
		osLabel := "linux"
		if i%2 == 1 {
			osLabel = "windows"
		}
		host := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
		lset := map[string]string{
			model.MetricNameLabel: "cpu_usage_ratio",
			"host":                host,
			"os":                  osLabel,
			"vendor":              vendor,
		}
		values := make([]float64, cfg.SamplesPerSeries)
		for t := 0; t < cfg.SamplesPerSeries; t++ {
			values[t] = rng.Float64() * 1.5
		}
		ds.Series[i] = scratchSeries{Labels: lset, Values: values}
	}
	return ds
}

// writeScratchData writes ds to path as indented JSON, creating parent dirs.
func writeScratchData(path string, ds scratchDataset) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(ds, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// readScratchData loads a dataset previously written by writeScratchData.
func readScratchData(path string) (scratchDataset, error) {
	var ds scratchDataset
	b, err := os.ReadFile(path)
	if err != nil {
		return ds, err
	}
	err = json.Unmarshal(b, &ds)
	return ds, err
}

// loadOrGenerateScratchData returns the dataset at path, generating and writing
// it with the current flag config if the file does not exist. This keeps the
// benchmarks runnable without a separate generation step while still preferring
// an explicit, inspectable fixture when one is present.
func loadOrGenerateScratchData(tb testing.TB, path string) scratchDataset {
	tb.Helper()
	ds, err := readScratchData(path)
	switch {
	case err == nil:
		return ds
	case os.IsNotExist(err):
		ds = generateScratchData(configFromFlags())
		if werr := writeScratchData(path, ds); werr != nil {
			tb.Fatalf("writing scratch data %s: %v", path, werr)
		}
		return ds
	default:
		tb.Fatalf("reading scratch data %s: %v", path, err)
		return scratchDataset{}
	}
}

// TestGenerateScratchData (re)generates the benchmark data fixture and logs the
// raw series and values it writes. Configure with -scratch.numSeries,
// -scratch.samplesPerSeries, -scratch.seed and -scratch.data, e.g.:
//
//	go test ./tsdb -run TestGenerateScratchData -v \
//	  -scratch.numSeries=10 -scratch.samplesPerSeries=100 \
//	  -scratch.data=testdata/scratch_benchdata.json
//
// It overwrites any existing file at the target path.
func TestGenerateScratchData(t *testing.T) {
	cfg := configFromFlags()
	ds := generateScratchData(cfg)
	noErr(writeScratchData(*scratchDataPath, ds))

	t.Logf("wrote %d series x %d samples (seed %d) to %s; selector %s=%q matches %d series",
		cfg.NumSeries, cfg.SamplesPerSeries, cfg.Seed, *scratchDataPath,
		cfg.SelName, cfg.SelValue, ds.matchedSeries())
	for i, s := range ds.Series {
		mark := ""
		if s.matched() {
			mark = " [matched]"
		}
		t.Logf("  series[%d]%s %s values=%v", i, mark, s.labelSet().String(), s.Values)
	}
}
