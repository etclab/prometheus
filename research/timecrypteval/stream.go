package timecrypteval

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	timecrypt "github.com/aashutoshpaudyal/timecrypt-go"
	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
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

type manifestFile struct {
	Streams []streamConfig `json:"streams"`
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
func loadStreams(keysDir string) (map[string]*encStream, error) {
	blob, err := os.ReadFile(filepath.Join(keysDir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("timecrypteval: reading manifest: %w", err)
	}
	var mf manifestFile
	if err := json.Unmarshal(blob, &mf); err != nil {
		return nil, fmt.Errorf("timecrypteval: parsing manifest: %w", err)
	}
	streams := make(map[string]*encStream, len(mf.Streams))
	for _, s := range mf.Streams {
		master, err := os.ReadFile(filepath.Join(keysDir, s.KeyFile))
		if err != nil {
			return nil, fmt.Errorf("timecrypteval: reading key %q: %w", s.KeyFile, err)
		}
		skm, err := timecrypt.NewStreamKeyManager(master, s.TreeDepth)
		if err != nil {
			return nil, fmt.Errorf("timecrypteval: stream key manager for %q: %w", s.Metric, err)
		}
		streams[s.Metric] = &encStream{
			metric:       s.Metric,
			timeIDMetric: s.TimeIDMetric,
			scale:        s.Scale,
			modBits:      s.ModBits,
			enc:          timecrypt.NewTimeCryptEncryptionBI(skm.TreeKeyRegression(), s.ModBits),
		}
	}
	return streams, nil
}

// decryptPoint decrypts one sample (timeID range [id,id]) to a plaintext float.
func (s *encStream) decryptPoint(residue *big.Int, timeID int64) (float64, error) {
	p, err := s.enc.DecryptMetadata(residue, timeID, timeID, 0)
	if err != nil {
		return 0, err
	}
	return timecrypt.FixedToFloat(timecrypt.SignedFromResidue(p, s.modBits), s.scale), nil
}

// decryptWindowSum decrypts the homomorphic sum of the window's samples.
//
// When the timeIDs are contiguous it uses HEAC's telescoping property: the
// server-side sum of the ciphertext residues decrypts with only the two
// boundary keys, so no per-sample key is ever materialised. When they are not
// contiguous (e.g. a scrape gap) it falls back to summing per-point
// decryptions, which is always correct but reveals each plaintext to the key
// holder.
func (s *encStream) decryptWindowSum(points []point) (float64, error) {
	if contiguous(points) {
		sum := new(big.Int)
		for _, p := range points {
			sum.Add(sum, p.residue) // server step: add ciphertexts, no keys.
		}
		from := points[0].timeID
		to := points[len(points)-1].timeID
		p, err := s.enc.DecryptMetadata(sum, from, to, 0)
		if err != nil {
			return 0, err
		}
		return timecrypt.FixedToFloat(timecrypt.SignedFromResidue(p, s.modBits), s.scale), nil
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

// seriesSamples is the per-series float samples read from storage, keyed for
// pairing the value series with its timeID companion.
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
	t       int64
	residue *big.Int
	timeID  int64
}

// collectSeries selects metric{matchers} over [mint,maxt] and returns the float
// samples per series, keyed by the series' non-name label fingerprint so the
// value and timeID series of the same target can be paired.
func collectSeries(ctx context.Context, q storage.Querier, metric string, matchers []*labels.Matcher, mint, maxt int64) (map[uint64]seriesSamples, error) {
	ms := make([]*labels.Matcher, 0, len(matchers)+1)
	ms = append(ms, labels.MustNewMatcher(labels.MatchEqual, model.MetricNameLabel, metric))
	ms = append(ms, matchers...)

	ss := q.Select(ctx, false, &storage.SelectHints{Start: mint, End: maxt}, ms...)
	out := map[uint64]seriesSamples{}
	builder := labels.NewBuilder(labels.EmptyLabels())
	for ss.Next() {
		series := ss.At()
		builder.Reset(series.Labels())
		stripped := builder.Del(model.MetricNameLabel).Labels()
		key := stripped.Hash()

		var samples []fpoint
		it := series.Iterator(nil)
		for it.Next() == chunkenc.ValFloat {
			ts, f := it.At()
			if ts < mint || ts > maxt {
				continue
			}
			samples = append(samples, fpoint{t: ts, f: f})
		}
		if err := it.Err(); err != nil {
			return nil, err
		}
		out[key] = seriesSamples{metric: stripped, samples: samples}
	}
	if err := ss.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

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
