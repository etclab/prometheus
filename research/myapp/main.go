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
// TODO: why are there to series?
//   - myapp_processed_ops_timeid the HEAC time index of that sample, so the
//     key-holding rule evaluator knows which keys decrypt each sample.
//
// Both series are produced together, atomically, at scrape time by a custom
// collector: each scrape encrypts the current plaintext value at the next
// contiguous timeID, so the value and its timeID can never desync and the
// evaluator's window aggregates line up with the key-regression tree.
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
	Metric       string  `json:"metric"`
	KeyFile      string  `json:"key_file"`
	TimeIDMetric string  `json:"timeid_metric"`
	Scale        float64 `json:"scale"`
	ModBits      int     `json:"mod_bits"`
	TreeDepth    int     `json:"tree_depth"`
}

type manifest struct {
	Streams []stream `json:"streams"`
}

// loadStream reads the manifest + master seed for one metric and builds the
// HEAC encryption scheme for it.
func loadStream(keysDir, metric string) (stream, *timecrypt.TimeCryptEncryptionBI) {
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
		return s, timecrypt.NewTimeCryptEncryptionBI(skm.TreeKeyRegression(), s.ModBits)
	}
	log.Fatalf("myapp: metric %q not found in manifest", metric)
	return stream{}, nil
}

// encCollector owns the plaintext value and emits its encryption on scrape.
type encCollector struct {
	mu         sync.Mutex
	value      float64
	nextTimeID int64

	enc        *timecrypt.TimeCryptEncryptionBI
	scale      float64
	valueDesc  *prometheus.Desc
	timeIDDesc *prometheus.Desc
}

func newEncCollector(s stream, enc *timecrypt.TimeCryptEncryptionBI) *encCollector {
	return &encCollector{
		enc:        enc,
		scale:      s.Scale,
		valueDesc:  prometheus.NewDesc(s.Metric, "TimeCrypt (HEAC) ciphertext of the processed-ops gauge; decrypts client-side.", nil, nil),
		timeIDDesc: prometheus.NewDesc(s.TimeIDMetric, "HEAC time index (key id) of the current myapp_processed_ops ciphertext.", nil, nil),
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
	ch <- c.timeIDDesc
}

// Collect encrypts the current value at the next contiguous timeID and emits
// the ciphertext + timeID as one consistent pair.
func (c *encCollector) Collect(ch chan<- prometheus.Metric) {
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
	flag.Parse()

	s, enc := loadStream(*keysDir, "myapp_processed_ops")

	reg := prometheus.NewRegistry()
	c := newEncCollector(s, enc)
	reg.MustRegister(c)
	go c.walk()

	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	log.Printf("myapp: serving encrypted metrics on %s (keys from %s)", *addr, *keysDir)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
