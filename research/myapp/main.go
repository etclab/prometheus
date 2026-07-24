// Command myapp is the demo scrape target for the encrypted-Prometheus
// experiment. It is the data *owner*: it random-walks a plaintext gauge
// internally but never exposes the plaintext. Instead it TimeCrypt-encrypts
// each value (HEAC, additively homomorphic) using key material from
// research/keys and exposes the ciphertext, so the Prometheus server only ever
// scrapes and stores encrypted values.
//
// Two series are exported:
//
//   - myapp_processed_ops        the HEAC ciphertext residue, carried as an
//     exact-integer float64 (the modulus is <= 2^52 so it survives the text
//     exposition format and XOR chunk storage without loss).
//
//   - myapp_processed_ops_timeid the HEAC time index of that sample, so the
//     key-holding rule evaluator knows which keys decrypt each sample.
//
// Both series are produced together, atomically, at scrape time by a custom
// collector: each scrape encrypts the current plaintext value at the next
// contiguous timeID, so the value and its timeID can never desync and the
// evaluator's window aggregates line up with the key-regression tree.
//
// Those are the series names of the TimeCrypt-only mode (-hermes=false). By
// default the label pairs are encrypted too: the same two series are then
// exposed as enc_series{sid=...} / enc_series_timeid{sid=...} and their real
// names and labels are indexed into Prometheus's Hermes index instead (see
// hermes.go). The value plane is identical in both modes.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	timecrypt "github.com/aashutoshpaudyal/timecrypt-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// stream mirrors the manifest entry written by research/keytool.
type stream struct {
	Metric  string `json:"metric"`
	KeyFile string `json:"key_file"`
	// companion HEAC time id metric name?
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

type manifest struct {
	Streams []stream     `json:"streams"`
	Hermes  hermesConfig `json:"hermes"`
}

// loadStream reads the manifest + master seed for one metric and builds the
// HEAC encryption scheme for it.
// TODO: HOMAC isn't added yet?
func loadStream(keysDir, metric string) (stream, hermesConfig, *timecrypt.TimeCryptEncryptionBI) {
	blob, err := os.ReadFile(filepath.Join(keysDir, "manifest.json"))
	if err != nil {
		log.Fatalf("myapp: reading manifest: %v (did you run keytool?)", err)
	}
	var m manifest
	if err := json.Unmarshal(blob, &m); err != nil {
		log.Fatalf("myapp: parsing manifest: %v", err)
	}
	for _, s := range m.Streams {
		if s.Metric != metric {
			continue
		}
		master, err := os.ReadFile(filepath.Join(keysDir, s.KeyFile))
		if err != nil {
			log.Fatalf("myapp: reading key file: %v", err)
		}
		// owner creates this per-stream
		skm, err := timecrypt.NewStreamKeyManager(master, s.TreeDepth)
		if err != nil {
			log.Fatalf("myapp: building stream key manager: %v", err)
		}
		return s, m.Hermes, timecrypt.NewTimeCryptEncryptionBI(skm.TreeKeyRegression(), s.ModBits)
	}
	log.Fatalf("myapp: metric %q not found in manifest", metric)
	return stream{}, hermesConfig{}, nil
}

// encCollector owns the plaintext value and emits its encryption on scrape.
//
// When plaintext is set it becomes the no-TimeCrypt demo source: it exposes the
// raw gauge directly (no encryption, no timeID companion) so the standalone
// plaintext rule evaluator (research/plaintexteval) can aggregate and threshold
// it over the normal Prometheus HTTP API.
type encCollector struct {
	mu         sync.Mutex
	value      float64
	nextTimeID int64

	plaintext  bool
	enc        *timecrypt.TimeCryptEncryptionBI
	scale      float64
	valueDesc  *prometheus.Desc
	timeIDDesc *prometheus.Desc
}

// newEncCollector builds the encrypted collector.
//
// With a sid (Hermes on) both series are exposed under generic metric names
// carrying nothing but that opaque series id: the real metric name and labels
// travel only as Hermes keywords, so Prometheus stores no plaintext label pair
// for this series.
//
// An empty sid is the TimeCrypt-only mode: the series keep their real names and
// their labels are left to Prometheus as usual, so only the values are
// encrypted. The HEAC ciphertext and its timeID companion are identical either
// way — the sid changes what the series is *called*, never what it carries.
func newEncCollector(s stream, enc *timecrypt.TimeCryptEncryptionBI, sid string) *encCollector {
	valueName, timeIDName := encSeriesMetric, encTimeIDMetric
	var sidLabels prometheus.Labels
	if sid == "" {
		valueName, timeIDName = s.Metric, s.TimeIDMetric
	} else {
		sidLabels = prometheus.Labels{sidLabel: sid}
	}
	return &encCollector{
		enc:        enc,
		scale:      s.Scale,
		valueDesc:  prometheus.NewDesc(valueName, "TimeCrypt (HEAC) ciphertext of an encrypted series; decrypts client-side.", nil, sidLabels),
		timeIDDesc: prometheus.NewDesc(timeIDName, "HEAC time index (key id) of the current ciphertext sample.", nil, sidLabels),
	}
}

// newPlainCollector builds the no-TimeCrypt variant: the same downward
// random-walk exposed as a plain gauge under the usual metric name, so
// research/configs/alerts.yml (delta(myapp_processed_ops[1m]) < 0) fires
// unchanged against real plaintext values.
func newPlainCollector() *encCollector {
	return &encCollector{
		plaintext: true,
		valueDesc: prometheus.NewDesc("myapp_processed_ops", "Plaintext processed-ops gauge (no TimeCrypt).", nil, nil),
	}
}

// walk advances the plaintext gauge once per step, biased downward so decreases
// are common and easy to alert on (90% down, 10% up). The plaintext never
// leaves this process.
func (c *encCollector) walk() {
	for {
		c.mu.Lock()
		if rand.Intn(10) < 9 {
			c.value--
		} else {
			c.value++
		}
		c.mu.Unlock()
		time.Sleep(1 * time.Second)
	}
}

func (c *encCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.valueDesc
	if !c.plaintext {
		ch <- c.timeIDDesc
	}
}

// Collect encrypts the current value at the next contiguous timeID and emits
// the ciphertext + timeID as one consistent pair. In plaintext mode it emits
// the raw gauge value instead.
func (c *encCollector) Collect(ch chan<- prometheus.Metric) {
	if c.plaintext {
		c.mu.Lock()
		v := c.value
		c.mu.Unlock()
		ch <- prometheus.MustNewConstMetric(c.valueDesc, prometheus.GaugeValue, v)
		return
	}

	c.mu.Lock()
	timeID := c.nextTimeID
	c.nextTimeID++
	v := c.value
	c.mu.Unlock()

	ct, err := c.enc.EncryptMetadata(big.NewInt(timecrypt.FloatToFixed(v, c.scale)), timeID, 0)
	if err != nil {
		log.Printf("myapp: encrypting sample at timeID %d: %v", timeID, err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.valueDesc, prometheus.GaugeValue, timecrypt.ResidueToFloat(ct))
	ch <- prometheus.MustNewConstMetric(c.timeIDDesc, prometheus.GaugeValue, float64(timeID))
}

func main() {
	keysDir := flag.String("keys-dir", "research/keys", "directory holding the TimeCrypt manifest and master seeds")
	addr := flag.String("addr", ":2112", "address to serve /metrics on")
	target := flag.String("target", "localhost:2112", "this target's identity: its writer class is looked up under this key in the manifest, and it is indexed as the instance label")
	prometheusURL := flag.String("prometheus-url", "http://localhost:9090", "base URL of the Prometheus hosting the encrypted index")
	plaintext := flag.Bool("plaintext", false, "expose myapp_processed_ops as a plain gauge (no TimeCrypt); used with the plaintext rule evaluator")
	hermesOn := flag.Bool("hermes", true, "index this target's (label, value) pairs into Prometheus's Hermes index and expose the series under an opaque id; with -hermes=false the series keeps its real name and labels and only its values are TimeCrypt-encrypted")
	flag.Parse()

	reg := prometheus.NewRegistry()
	var c *encCollector
	if *plaintext {
		c = newPlainCollector()
	} else if !*hermesOn {
		// TimeCrypt only: the values are still HEAC ciphertext, but the series is
		// exposed under its real name and Prometheus labels it as it labels any
		// other target.
		s, _, enc := loadStream(*keysDir, "myapp_processed_ops")
		c = newEncCollector(s, enc, "")
	} else {
		s, hc, enc := loadStream(*keysDir, "myapp_processed_ops")

		// The label set this target owns. It never leaves the process as
		// plaintext: every pair is encrypted into the Hermes index, and the
		// series itself is exposed carrying only the id derived from it.
		lset := map[string]string{
			"__name__": s.Metric,
			"job":      "myapp",
			"instance": *target,
		}

		wid, ok := hc.Writers[*target]
		if !ok {
			log.Fatalf("myapp: target %q has no writer class in the manifest", *target)
		}
		seed, err := os.ReadFile(filepath.Join(*keysDir, hc.SeedFile))
		if err != nil {
			log.Fatalf("myapp: reading Hermes seed: %v (did you run keytool?)", err)
		}
		hw, err := newHermesWriter(seed, wid, hc.NumWriters, *prometheusURL)
		if err != nil {
			log.Fatalf("myapp: building Hermes writer: %v", err)
		}
		docID, sid := hw.seriesID(lset)

		c = newEncCollector(s, enc, sid)
		go hw.indexWithRetry(lset, docID)
	}
	reg.MustRegister(c)
	go c.walk()

	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	switch {
	case *plaintext:
		log.Printf("myapp: serving plaintext metrics on %s", *addr)
	case *hermesOn:
		log.Printf("myapp: serving encrypted metrics on %s as %s (keys from %s)", *addr, *target, *keysDir)
	default:
		log.Printf("myapp: serving TimeCrypt-encrypted values on %s under plaintext labels, Hermes off (keys from %s)", *addr, *keysDir)
	}
	log.Fatal(http.ListenAndServe(*addr, nil))
}
