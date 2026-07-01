package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// toy128k1f domain parameters.
// Educational only. Do not use for real funds.
var (
	CurveP, _  = new(big.Int).SetString("cc3e373aa65e4fc92bfba193af40d4e7", 16)
	CurveA     = big.NewInt(0)
	CurveB     = big.NewInt(7)
	CurveGx, _ = new(big.Int).SetString("c10a8eb0ef340645a767114393fc4786", 16)
	CurveGy, _ = new(big.Int).SetString("a50d20b0925585547a2a396090e48f7a", 16)
	CurveN, _  = new(big.Int).SetString("cc3e373aa65e4fc91c93ff817b7e1259", 16)
)

const (
	AddressPrefix  = "tn1"
	PrivKeyPrefix  = "tnpriv"
	CoordSizeBytes = 16
)

type ECPoint struct {
	X   *big.Int `json:"x,omitempty"`
	Y   *big.Int `json:"y,omitempty"`
	Inf bool     `json:"inf"`
}

func GPoint() ECPoint   { return ECPoint{X: new(big.Int).Set(CurveGx), Y: new(big.Int).Set(CurveGy)} }
func Infinity() ECPoint { return ECPoint{Inf: true} }

func mod(v *big.Int) *big.Int {
	r := new(big.Int).Mod(v, CurveP)
	if r.Sign() < 0 {
		r.Add(r, CurveP)
	}
	return r
}

func invMod(v *big.Int) (*big.Int, error) {
	x := new(big.Int).Mod(v, CurveP)
	inv := new(big.Int).ModInverse(x, CurveP)
	if inv == nil {
		return nil, errors.New("no modular inverse")
	}
	return inv, nil
}

func OnCurve(P ECPoint) bool {
	if P.Inf {
		return true
	}
	if P.X == nil || P.Y == nil {
		return false
	}
	left := mod(new(big.Int).Mul(P.Y, P.Y))
	x2 := new(big.Int).Mul(P.X, P.X)
	x3 := new(big.Int).Mul(x2, P.X)
	right := mod(new(big.Int).Add(new(big.Int).Add(x3, new(big.Int).Mul(CurveA, P.X)), CurveB))
	return left.Cmp(right) == 0
}

func ECAdd(P, Q ECPoint) (ECPoint, error) {
	if P.Inf {
		return clonePoint(Q), nil
	}
	if Q.Inf {
		return clonePoint(P), nil
	}
	if P.X.Cmp(Q.X) == 0 {
		ys := mod(new(big.Int).Add(P.Y, Q.Y))
		if ys.Sign() == 0 {
			return Infinity(), nil
		}
	}

	var lambda *big.Int
	if P.X.Cmp(Q.X) == 0 && P.Y.Cmp(Q.Y) == 0 {
		numerator := new(big.Int).Add(new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(P.X, P.X)), CurveA)
		denominator := new(big.Int).Mul(big.NewInt(2), P.Y)
		inv, err := invMod(denominator)
		if err != nil {
			return ECPoint{}, err
		}
		lambda = mod(new(big.Int).Mul(numerator, inv))
	} else {
		numerator := new(big.Int).Sub(Q.Y, P.Y)
		denominator := new(big.Int).Sub(Q.X, P.X)
		inv, err := invMod(denominator)
		if err != nil {
			return ECPoint{}, err
		}
		lambda = mod(new(big.Int).Mul(numerator, inv))
	}
	x3 := mod(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(lambda, lambda), P.X), Q.X))
	y3 := mod(new(big.Int).Sub(new(big.Int).Mul(lambda, new(big.Int).Sub(P.X, x3)), P.Y))
	return ECPoint{X: x3, Y: y3}, nil
}

func ECMul(k *big.Int, P ECPoint) (ECPoint, error) {
	if k.Sign() < 0 {
		return ECPoint{}, errors.New("negative scalar")
	}
	kk := new(big.Int).Set(k)
	R := Infinity()
	A := clonePoint(P)
	for kk.Sign() > 0 {
		if kk.Bit(0) == 1 {
			var err error
			R, err = ECAdd(R, A)
			if err != nil {
				return ECPoint{}, err
			}
		}
		kk.Rsh(kk, 1)
		if kk.Sign() > 0 {
			var err error
			A, err = ECAdd(A, A)
			if err != nil {
				return ECPoint{}, err
			}
		}
	}
	return R, nil
}

func clonePoint(P ECPoint) ECPoint {
	if P.Inf {
		return Infinity()
	}
	return ECPoint{X: new(big.Int).Set(P.X), Y: new(big.Int).Set(P.Y)}
}

func RandomScalar() (*big.Int, error) {
	for {
		b := make([]byte, CoordSizeBytes)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		d := new(big.Int).SetBytes(b)
		if d.Sign() > 0 && d.Cmp(CurveN) < 0 {
			return d, nil
		}
	}
}

func PrivateToPublic(d *big.Int) (ECPoint, error) {
	if d.Sign() <= 0 || d.Cmp(CurveN) >= 0 {
		return ECPoint{}, errors.New("private key out of range")
	}
	return ECMul(d, GPoint())
}

func pointBytes(P ECPoint) ([]byte, error) {
	if P.Inf || P.X == nil || P.Y == nil {
		return nil, errors.New("cannot encode infinity")
	}
	xb := fixedBytes(P.X, CoordSizeBytes)
	yb := fixedBytes(P.Y, CoordSizeBytes)
	out := append([]byte{0x04}, xb...)
	out = append(out, yb...)
	return out, nil
}

func PublicKeyHex(P ECPoint) (string, error) {
	b, err := pointBytes(P)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func ParsePublicKeyHex(s string) (ECPoint, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return ECPoint{}, err
	}
	if len(raw) != 1+2*CoordSizeBytes || raw[0] != 0x04 {
		return ECPoint{}, errors.New("invalid toy public key encoding")
	}
	x := new(big.Int).SetBytes(raw[1 : 1+CoordSizeBytes])
	y := new(big.Int).SetBytes(raw[1+CoordSizeBytes:])
	P := ECPoint{X: x, Y: y}
	if !OnCurve(P) {
		return ECPoint{}, errors.New("public key not on toy128k1f")
	}
	return P, nil
}

func PrivateKeyHex(d *big.Int) string { return fmt.Sprintf("%032x", d) }
func ParsePrivateKeyHex(s string) (*big.Int, error) {
	d, ok := new(big.Int).SetString(strings.TrimSpace(s), 16)
	if !ok {
		return nil, errors.New("invalid private hex")
	}
	if d.Sign() <= 0 || d.Cmp(CurveN) >= 0 {
		return nil, errors.New("private key out of toy128k1f range")
	}
	return d, nil
}

func AddressFromPublicKeyHex(pub string) (string, error) {
	raw, err := hex.DecodeString(pub)
	if err != nil {
		return "", err
	}
	// Toynet128 address format:
	//   tn1 + Bech32 witness-v0 payload
	//   HRP: "tn"
	//   version: 0
	//   program: ToyHash160(pubkey) = SHA256(pubkey)[:20]
	//
	// This intentionally looks and behaves like a native SegWit address:
	// there is a separator, a witness version, 5-bit regrouping and a real
	// Bech32 checksum. It is NOT Bitcoin-compatible and must never accept
	// bc1/1/3/WIF mainnet formats.
	h1 := sha256.Sum256(raw)
	return EncodeToyAddress(h1[:20])
}

func VerifyAddress(addr string) bool {
	_, err := DecodeToyAddress(addr)
	return err == nil
}

func EncodeToyAddress(program []byte) (string, error) {
	if len(program) != 20 {
		return "", errors.New("toy address program must be 20 bytes")
	}
	data, err := convertBits(program, 8, 5, true)
	if err != nil {
		return "", err
	}
	// Witness version 0, followed by the 20-byte program converted to base32.
	data = append([]byte{0}, data...)
	return bech32Encode("tn", data)
}

func DecodeToyAddress(addr string) ([]byte, error) {
	hrp, data, err := bech32Decode(addr)
	if err != nil {
		return nil, err
	}
	if hrp != "tn" {
		return nil, errors.New("invalid Toynet HRP")
	}
	if len(data) == 0 || data[0] != 0 {
		return nil, errors.New("only Toycoin witness version 0 is supported")
	}
	program, err := convertBits(data[1:], 5, 8, false)
	if err != nil {
		return nil, err
	}
	if len(program) != 20 {
		return nil, errors.New("invalid Toycoin program length")
	}
	return program, nil
}

func fixedBytes(x *big.Int, size int) []byte {
	b := x.Bytes()
	if len(b) > size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// Bech32 implementation for Toycoin native addresses. It follows BIP-173
// checksum mechanics, but with Toynet HRP "tn" and ToyHash160 payloads.
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	generators := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if ((top >> uint(i)) & 1) == 1 {
				chk ^= generators[i]
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func bech32CreateChecksum(hrp string, data []byte) []byte {
	values := append(bech32HrpExpand(hrp), data...)
	values = append(values, []byte{0, 0, 0, 0, 0, 0}...)
	polymod := bech32Polymod(values) ^ 1
	checksum := make([]byte, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = byte((polymod >> uint(5*(5-i))) & 31)
	}
	return checksum
}

func bech32VerifyChecksum(hrp string, data []byte) bool {
	values := append(bech32HrpExpand(hrp), data...)
	return bech32Polymod(values) == 1
}

func bech32Encode(hrp string, data []byte) (string, error) {
	if hrp == "" {
		return "", errors.New("empty HRP")
	}
	for _, r := range hrp {
		if r < 33 || r > 126 || r >= 'A' && r <= 'Z' {
			return "", errors.New("invalid HRP")
		}
	}
	combined := append(append([]byte{}, data...), bech32CreateChecksum(hrp, data)...)
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, v := range combined {
		if v >= 32 {
			return "", errors.New("invalid bech32 value")
		}
		b.WriteByte(bech32Charset[v])
	}
	return b.String(), nil
}

func bech32Decode(s string) (string, []byte, error) {
	if s != strings.ToLower(s) && s != strings.ToUpper(s) {
		return "", nil, errors.New("mixed-case bech32 string")
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < 8 || len(s) > 90 {
		return "", nil, errors.New("invalid bech32 length")
	}
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, errors.New("invalid bech32 separator")
	}
	hrp := s[:pos]
	dataPart := s[pos+1:]
	data := make([]byte, len(dataPart))
	for i, r := range dataPart {
		idx := strings.IndexRune(bech32Charset, r)
		if idx < 0 {
			return "", nil, errors.New("invalid bech32 character")
		}
		data[i] = byte(idx)
	}
	if !bech32VerifyChecksum(hrp, data) {
		return "", nil, errors.New("invalid bech32 checksum")
	}
	return hrp, data[:len(data)-6], nil
}

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := uint(0)
	bits := uint(0)
	maxv := uint((1 << toBits) - 1)
	maxAcc := uint((1 << (fromBits + toBits - 1)) - 1)
	var ret []byte
	for _, value := range data {
		v := uint(value)
		if v>>fromBits != 0 {
			return nil, errors.New("invalid bit group")
		}
		acc = ((acc << fromBits) | v) & maxAcc
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, errors.New("invalid padding")
	}
	return ret, nil
}

func Sign(hash []byte, priv *big.Int) (string, error) {
	z := new(big.Int).SetBytes(hash)
	z.Mod(z, CurveN)
	for {
		k, err := RandomScalar()
		if err != nil {
			return "", err
		}
		R, err := ECMul(k, GPoint())
		if err != nil {
			return "", err
		}
		r := new(big.Int).Mod(R.X, CurveN)
		if r.Sign() == 0 {
			continue
		}
		kinv := new(big.Int).ModInverse(k, CurveN)
		if kinv == nil {
			continue
		}
		s := new(big.Int).Mul(r, priv)
		s.Add(s, z)
		s.Mul(s, kinv)
		s.Mod(s, CurveN)
		if s.Sign() == 0 {
			continue
		}
		return fmt.Sprintf("%x:%x", r, s), nil
	}
}

func Verify(hash []byte, sig string, pub ECPoint) bool {
	parts := strings.Split(sig, ":")
	if len(parts) != 2 {
		return false
	}
	r, ok := new(big.Int).SetString(parts[0], 16)
	if !ok {
		return false
	}
	s, ok := new(big.Int).SetString(parts[1], 16)
	if !ok {
		return false
	}
	if r.Sign() <= 0 || r.Cmp(CurveN) >= 0 || s.Sign() <= 0 || s.Cmp(CurveN) >= 0 {
		return false
	}
	z := new(big.Int).SetBytes(hash)
	z.Mod(z, CurveN)
	w := new(big.Int).ModInverse(s, CurveN)
	if w == nil {
		return false
	}
	u1 := new(big.Int).Mul(z, w)
	u1.Mod(u1, CurveN)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, CurveN)
	P1, err := ECMul(u1, GPoint())
	if err != nil {
		return false
	}
	P2, err := ECMul(u2, pub)
	if err != nil {
		return false
	}
	X, err := ECAdd(P1, P2)
	if err != nil || X.Inf {
		return false
	}
	v := new(big.Int).Mod(X.X, CurveN)
	return v.Cmp(r) == 0
}
