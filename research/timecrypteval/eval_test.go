package timecrypteval_test

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	timecrypt "github.com/aashutoshpaudyal/timecrypt-go"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/research/timecrypteval"
	"github.com/prometheus/prometheus/tsdb"
)

const (
	testMetric = "myapp_processed_ops"
	testTimeID = "myapp_processed_ops_timeid"
	testScale  = 1000.0
	testMod    = 32
	testDepth  = 20
)

// writeManifest writes a one-stream manifest + master seed into dir, matching
// what research/keytool produces.
func writeManifest(t *testing.T, dir string, master []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "s.key"), master, 0o600))
	manifest := `{"streams":[{"metric":"` + testMetric + `","key_file":"s.key","timeid_metric":"` +
		testTimeID + `","scale":1000,"mod_bits":32,"tree_depth":20}]}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644))
}

func withName(base labels.Labels, name string) labels.Labels {
	return labels.NewBuilder(base).Set(model.MetricNameLabel, name).Labels()
}

// storeEncrypted opens a TSDB and appends, for each plaintext value, the HEAC
// ciphertext (as an exact-integer float64) plus its companion timeID sample, as
// the encrypting client (myapp) and untrusted server (Prometheus) would. It
// returns the DB and the timestamp of the last sample (the eval time).
func storeEncrypted(t *testing.T, enc *timecrypt.TimeCryptEncryptionBI, values []float64) (*tsdb.DB, int64) {
	t.Helper()
	db, err := tsdb.Open(t.TempDir(), nil, nil, tsdb.DefaultOptions(), nil)
	require.NoError(t, err)

	app := db.Appender(context.Background())
	base := time.Now().Add(-time.Minute).Truncate(time.Second)
	series := labels.FromStrings("instance", "localhost:2112", "job", "myapp")
	valueSeries := withName(series, testMetric)
	timeIDSeries := withName(series, testTimeID)

	var lastTS int64
	for i, v := range values {
		ts := base.Add(time.Duration(i) * 10 * time.Second).UnixMilli()
		lastTS = ts
		ct, err := enc.EncryptMetadata(big.NewInt(timecrypt.FloatToFixed(v, testScale)), int64(i), 0)
		require.NoError(t, err)
		_, err = app.Append(0, valueSeries, ts, timecrypt.ResidueToFloat(ct))
		require.NoError(t, err)
		_, err = app.Append(0, timeIDSeries, ts, float64(i))
		require.NoError(t, err)
	}
	require.NoError(t, app.Commit())
	return db, lastTS
}

func newClientScheme(t *testing.T, master []byte) *timecrypt.TimeCryptEncryptionBI {
	t.Helper()
	skm, err := timecrypt.NewStreamKeyManager(master, testDepth)
	require.NoError(t, err)
	return timecrypt.NewTimeCryptEncryptionBI(skm.TreeKeyRegression(), testMod)
}

// TestDeltaAlertOverCiphertext is the end-to-end Layer-2 alert: a downward
// random walk stored as HEAC ciphertext fires `delta(...) < 0`, with the
// firing decision and reported value computed at the key holder.
func TestDeltaAlertOverCiphertext(t *testing.T) {
	ctx := context.Background()
	keysDir := t.TempDir()
	master, err := timecrypt.GenerateKey(16)
	require.NoError(t, err)
	writeManifest(t, keysDir, master)

	enc := newClientScheme(t, master)
	db, lastTS := storeEncrypted(t, enc, []float64{10, 9, 7, 4}) // net change -6.
	defer db.Close()

	delegateCalled := false
	delegate := func(context.Context, string, time.Time) (promql.Vector, error) {
		delegateCalled = true
		return nil, nil
	}
	qf, err := timecrypteval.New(delegate, db, keysDir)
	require.NoError(t, err)

	res, err := qf(ctx, "delta("+testMetric+"[1m]) < 0", time.UnixMilli(lastTS))
	require.NoError(t, err)
	require.False(t, delegateCalled, "encrypted rule must not fall through to the engine")
	require.Len(t, res, 1)
	require.InDelta(t, -6.0, res[0].F, 1e-6)
	require.Empty(t, res[0].Metric.Get(model.MetricNameLabel), "__name__ must be dropped, as delta() does")
	require.Equal(t, "myapp", res[0].Metric.Get("job"))
}

// TestDeltaAlertDoesNotFireWhenIncreasing checks the comparison really gates
// firing: an upward walk yields delta > 0 and produces no alert.
func TestDeltaAlertDoesNotFireWhenIncreasing(t *testing.T) {
	ctx := context.Background()
	keysDir := t.TempDir()
	master, err := timecrypt.GenerateKey(16)
	require.NoError(t, err)
	writeManifest(t, keysDir, master)

	enc := newClientScheme(t, master)
	db, lastTS := storeEncrypted(t, enc, []float64{1, 3, 6, 10}) // net change +9.
	defer db.Close()

	qf, err := timecrypteval.New(nil, db, keysDir)
	require.NoError(t, err)

	res, err := qf(ctx, "delta("+testMetric+"[1m]) < 0", time.UnixMilli(lastTS))
	require.NoError(t, err)
	require.Empty(t, res)
}

// TestSumOverTimeHomomorphic exercises the telescoping homomorphic sum path
// (contiguous timeIDs) and the threshold comparison at the key holder.
func TestSumOverTimeHomomorphic(t *testing.T) {
	ctx := context.Background()
	keysDir := t.TempDir()
	master, err := timecrypt.GenerateKey(16)
	require.NoError(t, err)
	writeManifest(t, keysDir, master)

	enc := newClientScheme(t, master)
	db, lastTS := storeEncrypted(t, enc, []float64{10, 9, 7, 4}) // sum 30.
	defer db.Close()

	qf, err := timecrypteval.New(nil, db, keysDir)
	require.NoError(t, err)

	res, err := qf(ctx, "sum_over_time("+testMetric+"[1m]) > 0", time.UnixMilli(lastTS))
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.InDelta(t, 30.0, res[0].F, 1e-6)

	res, err = qf(ctx, "avg_over_time("+testMetric+"[1m]) > 0", time.UnixMilli(lastTS))
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.InDelta(t, 30.0/4, res[0].F, 1e-6)
}

// TestUnsupportedQueryDelegates confirms anything outside the bounded encrypted
// shape passes through to the wrapped engine QueryFunc unchanged.
func TestUnsupportedQueryDelegates(t *testing.T) {
	ctx := context.Background()
	keysDir := t.TempDir()
	master, err := timecrypt.GenerateKey(16)
	require.NoError(t, err)
	writeManifest(t, keysDir, master)

	db, lastTS := storeEncrypted(t, newClientScheme(t, master), []float64{5, 4})
	defer db.Close()

	var got string
	delegate := func(_ context.Context, qs string, _ time.Time) (promql.Vector, error) {
		got = qs
		return promql.Vector{}, nil
	}
	qf, err := timecrypteval.New(delegate, db, keysDir)
	require.NoError(t, err)

	// Not an encrypted metric.
	_, err = qf(ctx, "up == 1", time.UnixMilli(lastTS))
	require.NoError(t, err)
	require.Equal(t, "up == 1", got)

	// Encrypted metric but unsupported shape (no comparison).
	got = ""
	_, err = qf(ctx, "delta("+testMetric+"[1m])", time.UnixMilli(lastTS))
	require.NoError(t, err)
	require.Equal(t, "delta("+testMetric+"[1m])", got)
}
