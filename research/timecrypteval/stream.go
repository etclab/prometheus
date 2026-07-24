package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	timecrypt "github.com/aashutoshpaudyal/timecrypt-go"
	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/model/labels"
)

// streamConfig mirrors one manifest entry written by research/keytool.
type streamConfig struct {
	Metric       string  `json:"metric"`
	KeyFile      string  `json:"key_file"`
	TimeIDMetric string  `json:"timeid_metric"`
	Scale        float64 `json:"scale"`
	ModBits      int     `json:"mod_bits"`
	TreeDepth    int     `json:"tree_depth"`
}

// hermesConfig mirrors the manifest's hermes block written by research/keytool.
type hermesConfig struct {
	SeedFile   string         `json:"seed_file"`
	NumWriters int            `json:"num_writers"`
	Writers    map[string]int `json:"writers"`
}

type manifestFile struct {
	Streams []streamConfig `json:"streams"`
	Hermes  hermesConfig   `json:"hermes"`
}

// encStream holds the per-metric decryption scheme and encoding parameters.
type encStream struct {
	metric       string
	timeIDMetric string
	scale        float64
	modBits      int
	enc          *timecrypt.TimeCryptEncryptionBI
}

// loadStreams reads the manifest and per-stream master seeds from keysDir and
// builds a decryption scheme per encrypted metric.
func loadStreams(keysDir string) (map[string]*encStream, hermesConfig, error) {
	blob, err := os.ReadFile(filepath.Join(keysDir, "manifest.json"))
	if err != nil {
		return nil, hermesConfig{}, fmt.Errorf("timecrypteval: reading manifest: %w", err)
	}
	var mf manifestFile
	if err := json.Unmarshal(blob, &mf); err != nil {
		return nil, hermesConfig{}, fmt.Errorf("timecrypteval: parsing manifest: %w", err)
	}
	streams := make(map[string]*encStream, len(mf.Streams))
	for _, s := range mf.Streams {
		master, err := os.ReadFile(filepath.Join(keysDir, s.KeyFile))
		if err != nil {
			return nil, hermesConfig{}, fmt.Errorf("timecrypteval: reading key %q: %w", s.KeyFile, err)
		}
		// TODO: a reader should only have keys (restricted) to the time range/resolution they're querying
		// TODO: not the entire stream's master key
		skm, err := timecrypt.NewStreamKeyManager(master, s.TreeDepth)
		if err != nil {
			return nil, hermesConfig{}, fmt.Errorf("timecrypteval: stream key manager for %q: %w", s.Metric, err)
		}
		streams[s.Metric] = &encStream{
			metric:       s.Metric,
			timeIDMetric: s.TimeIDMetric,
			scale:        s.Scale,
			modBits:      s.ModBits,
			enc:          timecrypt.NewTimeCryptEncryptionBI(skm.TreeKeyRegression(), s.ModBits),
		}
	}
	return streams, mf.Hermes, nil
}

// decryptPoint decrypts one sample (timeID range [id,id]) to a plaintext float.
func (s *encStream) decryptPoint(residue *big.Int, timeID int64) (float64, error) {
	p, err := s.enc.DecryptMetadata(residue, timeID, timeID, 0)
	if err != nil {
		return 0, err
	}
	// TODO: revisit the float to int to encrypted value conversion and back
	return timecrypt.FixedToFloat(timecrypt.SignedFromResidue(p, s.modBits), s.scale), nil
}

// decryptRangeSum decrypts a homomorphic range sum: the caller has already added
// the ciphertext residues over a contiguous window [from,to]; HEAC's telescoping
// property means the sum decrypts with only the two boundary keys, so no
// per-sample key is ever materialised. sumResidue is the (possibly un-reduced)
// integer sum of the residues; DecryptMetadata reduces it mod 2^modBits
// internally.
func (s *encStream) decryptRangeSum(sumResidue *big.Int, from, to int64) (float64, error) {
	p, err := s.enc.DecryptMetadata(sumResidue, from, to, 0)
	if err != nil {
		return 0, err
	}
	return timecrypt.FixedToFloat(timecrypt.SignedFromResidue(p, s.modBits), s.scale), nil
}

// decryptWindowSum decrypts the homomorphic sum of the window's samples from the
// raw per-sample points. It is the summable family's aggregation: when the
// timeIDs are contiguous it adds the ciphertext residues locally and uses the
// telescoping property (decryptRangeSum) to decrypt with only the two boundary
// keys; otherwise (a scrape gap) it falls back to summing per-point decryptions,
// which is always correct but reveals each plaintext to the key holder.
func (s *encStream) decryptWindowSum(points []point) (float64, error) {
	if contiguous(points) {
		sum := new(big.Int)
		for _, p := range points {
			sum.Add(sum, p.residue) // server step: add ciphertexts, no keys.
		}
		return s.decryptRangeSum(sum, points[0].timeID, points[len(points)-1].timeID)
	}

	var total float64
	for _, pt := range points {
		v, err := s.decryptPoint(pt.residue, pt.timeID)
		if err != nil {
			return 0, err
		}
		total += v
	}
	return total, nil
}

func contiguous(points []point) bool {
	for i := 1; i < len(points); i++ {
		if points[i].timeID != points[i-1].timeID+1 {
			return false
		}
	}
	return true
}

// seriesSamples is the per-series float samples read back from Prometheus, keyed
// for pairing the value series with its timeID companion.
type seriesSamples struct {
	metric  labels.Labels // labels with __name__ stripped (the pairing key + output labels).
	samples []fpoint
}

type fpoint struct {
	t int64
	f float64
}

// point is a value sample aligned with its HEAC timeID for one timestamp.
type point struct {
	t int64
	// forgot why this is called residue?
	residue *big.Int
	timeID  int64
}

// atp: okay range-vector vs instant-vector
//
// instant-vector - a list of metric values (or samples) for all the timeseries
// 	(matching a set of labels) at a given timestamp (timestamp and timeseries
// 	are two different things heres). (1D)
//
// range-vector - a list of instant-vector for a range of timestamps (2D)
// 	ie. (timeseries_id, timestamp)

// matrixToSeries turns a range-vector HTTP result into per-series float samples,
// keyed by the series' non-name label fingerprint so the value and timeID series
// of the same target can be paired.
func matrixToSeries(m model.Matrix) map[uint64]seriesSamples {
	out := make(map[uint64]seriesSamples, len(m))
	for _, ss := range m {
		lbls := stripName(ss.Metric)
		key := lbls.Hash()
		samples := make([]fpoint, 0, len(ss.Values))
		for _, v := range ss.Values {
			samples = append(samples, fpoint{t: int64(v.Timestamp), f: float64(v.Value)})
		}
		out[key] = seriesSamples{metric: lbls, samples: samples}
	}
	return out
}

// stripName converts an HTTP-result metric into labels.Labels with __name__
// removed, matching the pairing/output key used throughout the evaluator.
func stripName(m model.Metric) labels.Labels {
	b := labels.NewBuilder(labels.EmptyLabels())
	for name, val := range m {
		if name == model.MetricNameLabel {
			continue
		}
		b.Set(string(name), string(val))
	}
	return b.Labels()
}

// atp: review this later
// on surface it's obvious to understand what timeID is doing but look
// at an example

// pair aligns value samples with timeID samples by timestamp, decoding the
// float-carried ciphertext residue back to an exact integer.
func pair(vs, ts seriesSamples) []point {
	timeIDByTS := make(map[int64]int64, len(ts.samples))
	for _, s := range ts.samples {
		timeIDByTS[s.t] = int64(s.f)
	}
	points := make([]point, 0, len(vs.samples))
	for _, s := range vs.samples {
		id, ok := timeIDByTS[s.t]
		if !ok {
			continue
		}
		points = append(points, point{
			t:       s.t,
			residue: timecrypt.FloatToResidue(s.f),
			timeID:  id,
		})
	}
	return points
}
