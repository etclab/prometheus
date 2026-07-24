package main

// The Hermes half of myapp: this process is a Hermes *writer*. It encrypts its
// series' (label, value) pairs under its own writer key and submits them to the
// engine running inside Prometheus, so the server can resolve a label matcher to
// a series without ever learning the pair.
//
// The series itself goes over the wire carrying nothing but an opaque id — see
// seriesID — which is also the Hermes document id. Prometheus's ordinary index
// therefore maps that id to a series reference, and an encrypted search lands on
// the right series without any of its real labels being stored.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"slices"
	"time"

	"crypto/rand"

	"github.com/etclab/hermes/detrand"
	"github.com/etclab/hermes/hickae"
	hindex "github.com/etclab/hermes/index"
	"github.com/etclab/hermes/partition"
	"github.com/etclab/hermes/prf"
	"github.com/etclab/hermes/promadapter"
	"github.com/etclab/hermes/wire"
	"google.golang.org/protobuf/proto"
)

// The metric names the encrypted series are exposed under. They are deliberately
// generic: the real metric name travels only as a Hermes keyword, so every
// encrypted series in the system looks alike to the scraper.
const (
	encSeriesMetric = "enc_series"
	encTimeIDMetric = "enc_series_timeid"

	// sidLabel carries the opaque series id. It must match hermes.SIDLabel on
	// the Prometheus side.
	sidLabel = "sid"
)

// hermesWriter indexes this target's label pairs into Prometheus's encrypted
// index.
type hermesWriter struct {
	w   *hindex.Writer
	key [prf.KeySize]byte // this writer's secret key, also used to derive series ids.

	prometheusURL string
	client        *http.Client
}

// newHermesWriter derives this target's writer from the shared seed. Every role
// derives the same authority; a writer only ever uses its own key and its class
// binding key from it.
func newHermesWriter(seed []byte, wid, numWriters int, prometheusURL string) (*hermesWriter, error) {
	auth, err := hickae.NewAuthority(detrand.New(string(seed)), numWriters)
	if err != nil {
		return nil, fmt.Errorf("deriving authority: %w", err)
	}
	if wid < 0 || wid >= numWriters {
		return nil, fmt.Errorf("writer id %d outside the %d provisioned classes", wid, numWriters)
	}
	key := prf.DeriveWriterKey(seed, wid)
	return &hermesWriter{
		w:             hindex.NewWriter(wid, key, auth.PK, auth.CBK[wid], partition.DefaultConfig(), rand.Reader),
		key:           key,
		prometheusURL: prometheusURL,
		client:        &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// seriesID derives the opaque id of a label set: a PRF under the writer's own
// key, so ids are unguessable to anyone without it and cannot collide across
// writers. It is both the sid label value and the Hermes document id.
func (h *hermesWriter) seriesID(lset map[string]string) (uint64, string) {
	var buf []byte
	for _, name := range slices.Sorted(maps.Keys(lset)) {
		buf = append(buf, promadapter.Keyword(name, lset[name])...)
	}
	key := prf.PRF(h.key[:], buf)
	id := binary.BigEndian.Uint64(key[:8])
	return id, hex.EncodeToString(key[:8])
}

// index encrypts every label pair of lset under this writer and submits it,
// pointing each one at the series' opaque id.
func (h *hermesWriter) index(lset map[string]string, docID uint64) error {
	epoch, err := h.epoch()
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(lset)) {
		op, err := h.w.Update(epoch, promadapter.Keyword(name, lset[name]), docID)
		if err != nil {
			return fmt.Errorf("encrypting %s: %w", name, err)
		}
		if err := h.submit(op); err != nil {
			return fmt.Errorf("submitting %s: %w", name, err)
		}
	}
	return nil
}

// epoch fetches the engine's current epoch encoding. The engine owns the clock,
// so a writer must stamp its updates with what the server reports.
func (h *hermesWriter) epoch() (string, error) {
	resp, err := h.client.Get(h.prometheusURL + "/api/v1/hermes/epoch")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("epoch: %s: %s", resp.Status, body)
	}
	var out struct {
		Data struct {
			Epoch string `json:"epoch"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("epoch: %w", err)
	}
	return out.Data.Epoch, nil
}

// submit posts one encrypted update to the engine.
func (h *hermesWriter) submit(op *hindex.UpdateOp) error {
	req, err := wire.UpdateToProto(h.w.WID(), op)
	if err != nil {
		return err
	}
	blob, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	resp, err := h.client.Post(h.prometheusURL+"/api/v1/hermes/update",
		"application/x-protobuf", bytes.NewReader(blob))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// An accepted update carries no payload, so the API answers 204.
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("update: %s: %s", resp.Status, body)
	}
	return nil
}

// indexWithRetry keeps trying until Prometheus is up and has accepted every
// pair. Indexing happens once per process: the engine holds the encrypted index
// in memory only, so a Prometheus restart requires restarting the targets too.
func (h *hermesWriter) indexWithRetry(lset map[string]string, docID uint64) {
	for attempt := 1; ; attempt++ {
		err := h.index(lset, docID)
		if err == nil {
			log.Printf("myapp: indexed %d encrypted label pairs as sid %016x", len(lset), docID)
			return
		}
		log.Printf("myapp: indexing attempt %d failed: %v", attempt, err)
		time.Sleep(2 * time.Second)
	}
}
