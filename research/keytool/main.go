// Command keytool is the trusted authority for the encrypted-Prometheus demo:
// it generates the TimeCrypt keying material that the scrape target (myapp)
// uses to encrypt values and that the Prometheus rule evaluator uses to decrypt
// aggregates. It writes one 16-byte master seed per stream plus a manifest
// describing how each encrypted metric is encoded.
//
// It is intentionally simple and idempotent: existing key files are left alone
// so re-running the demo does not rotate keys out from under stored ciphertext.
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	timecrypt "github.com/aashutoshpaudyal/timecrypt-go"
)

// Stream describes the encryption parameters of one encrypted metric. The same
// struct is read by myapp (to encrypt) and by the Prometheus evaluator (to
// decrypt), so the JSON tags are the shared contract.
type Stream struct {
	Metric       string `json:"metric"`        // the encrypted gauge's metric name.
	KeyFile      string `json:"key_file"`      // master-seed file, relative to the manifest dir.
	TimeIDMetric string `json:"timeid_metric"` // companion gauge carrying each sample's timeID.
	// TODO: think about out the bits,chunks,scale
	Scale     float64 `json:"scale"`      // fixed-point scale (float -> int64).
	ModBits   int     `json:"mod_bits"`   // HEAC modulus bit width (<= 52 for float64-exact transport).
	TreeDepth int     `json:"tree_depth"` // key-regression tree depth (2^depth time steps).
}

// Hermes describes the key material of the encrypted inverted index. Every role
// — the scrape targets (writers), Prometheus (the engine) and the rule evaluator
// (the reader) — derives its keys from the same seed, which is the prototype's
// stand-in for a key-distribution channel.
type Hermes struct {
	SeedFile   string         `json:"seed_file"`   // shared seed file, relative to the manifest dir.
	NumWriters int            `json:"num_writers"` // writer classes provisioned by the trusted setup.
	Writers    map[string]int `json:"writers"`     // scrape target address -> writer class id.
}

// Manifest is the set of encrypted streams plus the encrypted-index key
// material, written to manifest.json.
type Manifest struct {
	Streams []Stream `json:"streams"`
	Hermes  Hermes   `json:"hermes"`
}

// hermesSeedLen is the size of the shared Hermes seed. It feeds a SHA-256
// counter stream, so 32 bytes matches the derivation's own security level.
const hermesSeedLen = 32

func main() {
	keysDir := flag.String("keys-dir", "research/keys", "directory to write key material and manifest into")
	flag.Parse()

	// The demo has a single encrypted stream. Adding more is a matter of
	// listing them here (one master seed per distinct series / label set).
	manifest := Manifest{Streams: []Stream{{
		Metric:       "myapp_processed_ops",
		KeyFile:      "myapp_processed_ops.key",
		TimeIDMetric: "myapp_processed_ops_timeid",
		Scale:        1000,
		// HEAC modulus bit width. It must (a) be <= 52 so residues are
		// float64-exact for text/chunk transport, and (b) divide the 128-bit
		// PRF output so timecrypt key derivation works (DeriveKey folds the
		// output into 128/bits partitions). 32 is the largest power-of-two
		// satisfying both; it leaves a signed plaintext range of ~+-2^31/scale.
		ModBits:   32,
		TreeDepth: 20,
	}}, Hermes: Hermes{
		SeedFile:   "hermes.seed",
		NumWriters: 4,
		// Two demo targets index encrypted label pairs; the remaining classes
		// are provisioned so more targets can join without a new trusted setup.
		Writers: map[string]int{
			"localhost:2112": 0,
			"localhost:2113": 1,
		},
	}}

	if err := os.MkdirAll(*keysDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "keytool:", err)
		os.Exit(1)
	}

	for _, s := range manifest.Streams {
		path := filepath.Join(*keysDir, s.KeyFile)
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("keytool: %s already exists, keeping it\n", path)
			continue
		} else if !os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "keytool:", err)
			os.Exit(1)
		}
		master, err := timecrypt.GenerateKey(16)
		if err != nil {
			fmt.Fprintln(os.Stderr, "keytool:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(path, master, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "keytool:", err)
			os.Exit(1)
		}
		fmt.Printf("keytool: wrote master seed %s (%d bytes)\n", path, len(master))
	}

	// The Hermes seed is generated on the same terms as the TimeCrypt seeds:
	// once, and never rotated out from under state that was encrypted with it.
	hermesPath := filepath.Join(*keysDir, manifest.Hermes.SeedFile)
	if _, err := os.Stat(hermesPath); err == nil {
		fmt.Printf("keytool: %s already exists, keeping it\n", hermesPath)
	} else if !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "keytool:", err)
		os.Exit(1)
	} else {
		seed := make([]byte, hermesSeedLen)
		if _, err := rand.Read(seed); err != nil {
			fmt.Fprintln(os.Stderr, "keytool:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(hermesPath, seed, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "keytool:", err)
			os.Exit(1)
		}
		fmt.Printf("keytool: wrote Hermes seed %s (%d bytes, %d writer classes)\n",
			hermesPath, len(seed), manifest.Hermes.NumWriters)
	}

	manifestPath := filepath.Join(*keysDir, "manifest.json")
	blob, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "keytool:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(manifestPath, append(blob, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "keytool:", err)
		os.Exit(1)
	}
	fmt.Printf("keytool: wrote manifest %s\n", manifestPath)
}
