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
	Metric  string `json:"metric"`   // the encrypted gauge's metric name.
	KeyFile string `json:"key_file"` // master-seed file, relative to the manifest dir.
	// TODO: here
	TimeIDMetric string `json:"timeid_metric"` // companion gauge carrying each sample's timeID.
	// TODO: start: think about out the bits,chunks,scale
	Scale   float64 `json:"scale"`    // fixed-point scale (float -> int64).
	ModBits int     `json:"mod_bits"` // HEAC modulus bit width (<= 52 for float64-exact transport).
	// TODO: end
	TreeDepth int `json:"tree_depth"` // key-regression tree depth (2^depth time steps).
}

// Manifest is the set of encrypted streams, written to manifest.json.
type Manifest struct {
	Streams []Stream `json:"streams"`
}

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
	}}}

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
