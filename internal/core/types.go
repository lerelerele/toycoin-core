package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	NetworkName            = "toynet128"
	Ticker                 = "TOY"
	DefaultRPCPort         = 28443
	DefaultP2PPort         = 28444
	GenesisTime      int64 = 1782856800 // 2026-06-30 12:00:00 UTC
	GenesisMessage         = "Toynet128 Genesis - Toycoin Core educational network 2026"
	Coin                   = int64(100000000)
	DefaultReward          = int64(50) * Coin
	DefaultBits            = 3 // leading hex zeroes. Keep low for classroom mining.
	CoinbaseMaturity       = 2
	DefaultFee             = int64(100000) // 0.001 TOY
)

type TxIn struct {
	PrevTxID  string `json:"prev_txid"`
	Vout      int    `json:"vout"`
	Signature string `json:"signature"`
	PubKey    string `json:"pub_key"`
}

type TxOut struct {
	Value   int64  `json:"value"`
	Address string `json:"address"`
}

type Transaction struct {
	TxID     string  `json:"txid"`
	Version  int     `json:"version"`
	Vin      []TxIn  `json:"vin"`
	Vout     []TxOut `json:"vout"`
	Locktime int64   `json:"locktime"`
	Coinbase bool    `json:"coinbase"`
	Message  string  `json:"message,omitempty"`
}

type BlockHeader struct {
	Version    int    `json:"version"`
	PrevHash   string `json:"prev_hash"`
	MerkleRoot string `json:"merkle_root"`
	Time       int64  `json:"time"`
	Bits       int    `json:"bits"`
	Nonce      uint64 `json:"nonce"`
	Height     int    `json:"height"`
}

type Block struct {
	Hash   string        `json:"hash"`
	Header BlockHeader   `json:"header"`
	Tx     []Transaction `json:"tx"`
}

type UTXO struct {
	TxID     string `json:"txid"`
	Vout     int    `json:"vout"`
	Value    int64  `json:"value"`
	Address  string `json:"address"`
	Height   int    `json:"height"`
	Coinbase bool   `json:"coinbase"`
}

type WalletKey struct {
	Address string `json:"address"`
	PrivHex string `json:"priv_hex"`
	PubHex  string `json:"pub_hex"`
	Created int64  `json:"created"`
}

type Wallet struct {
	Name string      `json:"name"`
	Keys []WalletKey `json:"keys"`
}

type State struct {
	Network      string                 `json:"network"`
	Blocks       []Block                `json:"blocks"`
	UTXO         map[string]UTXO        `json:"utxo"`
	Mempool      []Transaction          `json:"mempool"`
	Wallets      map[string]*Wallet     `json:"wallets"`
	ActiveWallet string                 `json:"active_wallet"`
	Peers        []string               `json:"peers"`
	Meta         map[string]interface{} `json:"meta"`
}

func NewState() (*State, error) {
	g, err := GenesisBlock()
	if err != nil {
		return nil, err
	}
	return &State{
		Network: NetworkName,
		Blocks:  []Block{g},
		UTXO:    map[string]UTXO{},
		Mempool: []Transaction{},
		Wallets: map[string]*Wallet{},
		Meta:    map[string]interface{}{"created": time.Now().Unix()},
	}, nil
}

func UTXOKey(txid string, vout int) string { return fmt.Sprintf("%s:%d", txid, vout) }

func DoubleSHA256(data []byte) []byte {
	h1 := sha256.Sum256(data)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

func HashHex(data []byte) string { return hex.EncodeToString(DoubleSHA256(data)) }

func (tx Transaction) IsCoinbase() bool { return tx.Coinbase || len(tx.Vin) == 0 }

func (tx *Transaction) ComputeTxID() string {
	copyTx := *tx
	copyTx.TxID = ""
	b, _ := json.Marshal(copyTx)
	return HashHex(b)
}

func (tx Transaction) SigningHash() []byte {
	copyTx := tx
	copyTx.TxID = ""
	// Deep-copy slices before clearing signatures; slices in Go share backing arrays.
	copyTx.Vin = append([]TxIn(nil), tx.Vin...)
	copyTx.Vout = append([]TxOut(nil), tx.Vout...)
	for i := range copyTx.Vin {
		copyTx.Vin[i].Signature = ""
	}
	b, _ := json.Marshal(copyTx)
	return DoubleSHA256(b)
}

func MerkleRoot(txs []Transaction) string {
	if len(txs) == 0 {
		return HashHex([]byte(""))
	}
	hashes := make([][]byte, len(txs))
	for i, tx := range txs {
		raw, _ := hex.DecodeString(tx.TxID)
		if len(raw) == 0 {
			raw = DoubleSHA256([]byte(tx.TxID))
		}
		hashes[i] = raw
	}
	for len(hashes) > 1 {
		var next [][]byte
		for i := 0; i < len(hashes); i += 2 {
			left := hashes[i]
			right := left
			if i+1 < len(hashes) {
				right = hashes[i+1]
			}
			combined := append(append([]byte{}, left...), right...)
			next = append(next, DoubleSHA256(combined))
		}
		hashes = next
	}
	return hex.EncodeToString(hashes[0])
}

func (h BlockHeader) Hash() string {
	b, _ := json.Marshal(h)
	return HashHex(b)
}

func MeetsTarget(hash string, bits int) bool {
	return strings.HasPrefix(hash, strings.Repeat("0", bits))
}

func CoinbaseTx(to string, value int64, height int, msg string) Transaction {
	tx := Transaction{
		Version:  1,
		Vin:      []TxIn{},
		Vout:     []TxOut{{Value: value, Address: to}},
		Locktime: 0,
		Coinbase: true,
		Message:  fmt.Sprintf("%s height=%d", msg, height),
	}
	tx.TxID = tx.ComputeTxID()
	return tx
}

func GenesisBlock() (Block, error) {
	cb := CoinbaseTx("tn1GENESIS000000000000000000000000000", 0, 0, GenesisMessage)
	b := Block{
		Header: BlockHeader{Version: 1, PrevHash: strings.Repeat("0", 64), Time: GenesisTime, Bits: DefaultBits, Height: 0},
		Tx:     []Transaction{cb},
	}
	b.Header.MerkleRoot = MerkleRoot(b.Tx)
	for nonce := uint64(0); ; nonce++ {
		b.Header.Nonce = nonce
		h := b.Header.Hash()
		if MeetsTarget(h, b.Header.Bits) {
			b.Hash = h
			return b, nil
		}
	}
}

func FormatAmount(v int64) string {
	sign := ""
	if v < 0 {
		sign = "-"
		v = -v
	}
	return fmt.Sprintf("%s%d.%08d", sign, v/Coin, v%Coin)
}

func ParseAmount(s string) (int64, error) {
	s = strings.TrimSpace(s)
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	}
	parts := strings.SplitN(s, ".", 2)
	whole := int64(0)
	for _, c := range parts[0] {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid amount")
		}
		whole = whole*10 + int64(c-'0')
	}
	frac := int64(0)
	if len(parts) == 2 {
		f := parts[1]
		if len(f) > 8 {
			return 0, fmt.Errorf("too many decimals")
		}
		for len(f) < 8 {
			f += "0"
		}
		for _, c := range f {
			if c < '0' || c > '9' {
				return 0, fmt.Errorf("invalid amount")
			}
			frac = frac*10 + int64(c-'0')
		}
	}
	out := whole*Coin + frac
	if neg {
		out = -out
	}
	return out, nil
}
