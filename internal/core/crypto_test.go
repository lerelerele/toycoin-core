package core

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"
)

// --- Bech32 / address format ---

func TestEncodeDecodeToyAddressRoundTrip(t *testing.T) {
	// A 20-byte witness program (like ToyHash160).
	program := sha256.Sum256([]byte("toycoin-test-program"))
	prog20 := program[:20]

	addr, err := EncodeToyAddress(prog20)
	if err != nil {
		t.Fatalf("EncodeToyAddress: %v", err)
	}
	if !strings.HasPrefix(addr, "tn1q") {
		t.Fatalf("address %q must start with tn1q", addr)
	}
	got, err := DecodeToyAddress(addr)
	if err != nil {
		t.Fatalf("DecodeToyAddress: %v", err)
	}
	if !bytes.Equal(got, prog20) {
		t.Fatalf("round-trip mismatch: got %x want %x", got, prog20)
	}
}

func TestVerifyAddressAcceptsKnownGood(t *testing.T) {
	// Generate a real, well-formed address and confirm it validates.
	program := sha256.Sum256([]byte("toynet128-good-address"))
	good, err := EncodeToyAddress(program[:20])
	if err != nil {
		t.Fatalf("EncodeToyAddress: %v", err)
	}
	if !VerifyAddress(good) {
		t.Fatalf("VerifyAddress should accept a freshly-encoded address: %q", good)
	}
}

func TestVerifyAddressRejectsTypo(t *testing.T) {
	good := "tn1q8z4h8k7k0q7vwrnvh0aqt7j7q0xp6mcmv7vx9w"
	// Flip the last checksum character; a single change should break the checksum.
	bad := good[:len(good)-1]
	if good[len(good)-1] == 'l' {
		bad += "q"
	} else {
		bad += "l"
	}
	if VerifyAddress(bad) {
		t.Fatalf("VerifyAddress should reject a typo'd address: %q", bad)
	}
}

func TestVerifyAddressRejectsWrongHRP(t *testing.T) {
	// A Bitcoin mainnet bc1-style address must not validate as Toynet.
	for _, bad := range []string{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", ""} {
		if VerifyAddress(bad) {
			t.Fatalf("VerifyAddress should reject %q", bad)
		}
	}
}

func TestConvertBitsRoundTrip(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0xff, 0x10, 0x99, 0xaa, 0x00, 0x7f}
	enc, err := convertBits(data, 8, 5, true)
	if err != nil {
		t.Fatalf("encode 8->5: %v", err)
	}
	dec, err := convertBits(enc, 5, 8, false)
	if err != nil {
		t.Fatalf("decode 5->8: %v", err)
	}
	if !bytes.Equal(dec, data) {
		t.Fatalf("convertBits round-trip mismatch: got %x want %x", dec, data)
	}
}

// --- ECDSA on toy128k1f ---

func TestECDSASignVerify(t *testing.T) {
	priv, err := RandomScalar()
	if err != nil {
		t.Fatalf("RandomScalar: %v", err)
	}
	pub, err := PrivateToPublic(priv)
	if err != nil {
		t.Fatalf("PrivateToPublic: %v", err)
	}
	hash := DoubleSHA256([]byte("message to sign"))

	sig, err := Sign(hash, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(hash, sig, pub) {
		t.Fatalf("Verify should accept a valid signature")
	}
}

func TestECDSARejectTamperedSignature(t *testing.T) {
	priv, _ := RandomScalar()
	pub, _ := PrivateToPublic(priv)
	hash := DoubleSHA256([]byte("msg"))
	sig, _ := Sign(hash, priv)

	// Mutate the signature's s value.
	parts := strings.SplitN(sig, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected sig format %q", sig)
	}
	tampered := parts[0] + ":" + "1"
	if Verify(hash, tampered, pub) {
		t.Fatalf("Verify must reject a tampered signature")
	}
}

func TestECDSARejectTamperedHash(t *testing.T) {
	priv, _ := RandomScalar()
	pub, _ := PrivateToPublic(priv)
	hash := DoubleSHA256([]byte("original message"))
	sig, _ := Sign(hash, priv)

	other := DoubleSHA256([]byte("different message"))
	if Verify(other, sig, pub) {
		t.Fatalf("Verify must reject a signature over a different hash")
	}
}

func TestParsePublicKeyHexRejectsOffCurve(t *testing.T) {
	// A point that is not on y^2 = x^3 + 7 (random big ints not satisfying the curve).
	off := ECPoint{
		X: big.NewInt(12345),
		Y: big.NewInt(67890),
	}
	hex, err := PublicKeyHex(off)
	if err != nil {
		t.Fatalf("PublicKeyHex encoding failed: %v", err)
	}
	if _, err := ParsePublicKeyHex(hex); err == nil {
		t.Fatalf("ParsePublicKeyHex must reject an off-curve point")
	}
}

func TestOnCurveGeneratorAndDouble(t *testing.T) {
	G := GPoint()
	if !OnCurve(G) {
		t.Fatalf("generator must be on the curve")
	}
	// 2G via ECAdd(G,G) must also be on the curve and equal ECMul(2,G).
	doubled, err := ECAdd(G, G)
	if err != nil {
		t.Fatalf("ECAdd(G,G): %v", err)
	}
	if !OnCurve(doubled) {
		t.Fatalf("2G must be on the curve")
	}
	twoG, err := ECMul(big.NewInt(2), G)
	if err != nil {
		t.Fatalf("ECMul(2,G): %v", err)
	}
	if doubled.X.Cmp(twoG.X) != 0 || doubled.Y.Cmp(twoG.Y) != 0 {
		t.Fatalf("ECAdd(G,G) != ECMul(2,G): %+v vs %+v", doubled, twoG)
	}
}

// --- Amount parsing/formatting ---

func TestParseAmountRoundTrip(t *testing.T) {
	// FormatAmount always normalizes to 8 decimals, so we compare by re-parsing
	// the formatted output rather than by exact string equality.
	cases := []string{"0", "0.00000000", "1.5", "50.001", "100", "0.00000001", "21.00000000"}
	for _, c := range cases {
		v, err := ParseAmount(c)
		if err != nil {
			t.Fatalf("ParseAmount(%q): %v", c, err)
		}
		formatted := FormatAmount(v)
		v2, err := ParseAmount(formatted)
		if err != nil {
			t.Fatalf("re-ParseAmount(%q): %v", formatted, err)
		}
		if v != v2 {
			t.Fatalf("round-trip value mismatch for %q: %d vs %d", c, v, v2)
		}
	}
}

func TestParseAmountRejectsTooManyDecimals(t *testing.T) {
	if _, err := ParseAmount("1.123456789"); err == nil {
		t.Fatalf("ParseAmount must reject more than 8 decimals")
	}
}

func TestParseAmountNegative(t *testing.T) {
	v, err := ParseAmount("-1.5")
	if err != nil {
		t.Fatalf("ParseAmount(-1.5): %v", err)
	}
	if v >= 0 {
		t.Fatalf("expected negative amount, got %d", v)
	}
	if got := FormatAmount(v); !strings.HasPrefix(got, "-") {
		t.Fatalf("FormatAmount of negative should start with -: %q", got)
	}
}
