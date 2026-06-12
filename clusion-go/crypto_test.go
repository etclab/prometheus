package clusion

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestAESCMAC_RFC4493 checks the hand-rolled AES-CMAC against the known-answer
// test vectors from RFC 4493 (Appendix), validating subkey generation and all
// three message-length cases (empty, exact block multiple, partial last block).
func TestAESCMAC_RFC4493(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	cases := []struct {
		name    string
		msgHex  string
		wantHex string
	}{
		{"empty", "", "bb1d6929e95937287fa37d129b756746"},
		{"16B", "6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		{"40B", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
		{"64B", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "51f0bebf7e3b9d92fc49741779363cfe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := aesCMAC(key, mustHex(t, c.msgHex))
			if err != nil {
				t.Fatal(err)
			}
			if want := mustHex(t, c.wantHex); !bytes.Equal(got, want) {
				t.Fatalf("AES-CMAC mismatch:\n got  %x\n want %x", got, want)
			}
		})
	}
}

// TestAESCTRStringRoundTrip checks that EncryptAESCTRString/DecryptAESCTRString
// recover the original identifier after stripping the terminator + padding.
func TestAESCTRStringRoundTrip(t *testing.T) {
	key := GenerateHmac([]byte("master"), "enc") // 32-byte key
	for _, id := range []string{"0", "12345", "127.0.0.1:linux:intel"} {
		iv := RandomBytes(ivSize)
		ct, err := EncryptAESCTRString(key, iv, id, 64)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := DecryptAESCTRString(ct, key)
		if err != nil {
			t.Fatal(err)
		}
		got := splitFirst(string(pt), fileIDTerminator)
		if got != id {
			t.Fatalf("round-trip: got %q want %q", got, id)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func splitFirst(s, sep string) string {
	if i := indexOf(s, sep); i >= 0 {
		return s[:i]
	}
	return s
}

func indexOf(s, sub string) int {
	return bytes.Index([]byte(s), []byte(sub))
}
