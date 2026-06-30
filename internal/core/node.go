package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type Node struct {
	mu        sync.Mutex
	State     *State
	DataDir   string
	StateFile string
	Peers     []string
}

func DefaultDataDir() string {
	if runtime.GOOS == "windows" {
		if app := os.Getenv("APPDATA"); app != "" {
			return filepath.Join(app, "Toycoin", NetworkName)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".toycoin", NetworkName)
	}
	return filepath.Join(".", "toycoin-data", NetworkName)
}

func LoadNode(datadir string, peers []string) (*Node, error) {
	if datadir == "" {
		datadir = DefaultDataDir()
	}
	if err := os.MkdirAll(datadir, 0700); err != nil {
		return nil, err
	}
	stateFile := filepath.Join(datadir, "state.json")
	var st *State
	if raw, err := os.ReadFile(stateFile); err == nil {
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, err
		}
		if st.UTXO == nil {
			st.UTXO = map[string]UTXO{}
		}
		if st.Wallets == nil {
			st.Wallets = map[string]*Wallet{}
		}
		if st.Meta == nil {
			st.Meta = map[string]interface{}{}
		}
	} else {
		var err error
		st, err = NewState()
		if err != nil {
			return nil, err
		}
	}
	st.Peers = mergePeers(st.Peers, peers)
	n := &Node{State: st, DataDir: datadir, StateFile: stateFile, Peers: st.Peers}
	if err := n.Save(); err != nil {
		return nil, err
	}
	return n, nil
}

func mergePeers(a, b []string) []string {
	m := map[string]bool{}
	var out []string
	for _, p := range append(a, b...) {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "http://") && !strings.HasPrefix(p, "https://") {
			p = "http://" + p
		}
		if !m[p] {
			m[p] = true
			out = append(out, p)
		}
	}
	return out
}

func (n *Node) Save() error {
	tmp := n.StateFile + ".tmp"
	raw, err := json.MarshalIndent(n.State, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, n.StateFile)
}

func (n *Node) Tip() Block  { return n.State.Blocks[len(n.State.Blocks)-1] }
func (n *Node) Height() int { return len(n.State.Blocks) - 1 }

func (n *Node) CreateWallet(name string) (*Wallet, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("wallet name required")
	}
	if w, ok := n.State.Wallets[name]; ok {
		n.State.ActiveWallet = name
		_ = n.Save()
		return w, nil
	}
	w := &Wallet{Name: name, Keys: []WalletKey{}}
	n.State.Wallets[name] = w
	n.State.ActiveWallet = name
	if err := n.Save(); err != nil {
		return nil, err
	}
	return w, nil
}

func (n *Node) activeWallet() (*Wallet, error) {
	if n.State.ActiveWallet == "" {
		return nil, errors.New("no active wallet; run createwallet first")
	}
	w := n.State.Wallets[n.State.ActiveWallet]
	if w == nil {
		return nil, errors.New("active wallet missing")
	}
	return w, nil
}

func (n *Node) GetNewAddress() (WalletKey, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	w, err := n.activeWallet()
	if err != nil {
		return WalletKey{}, err
	}
	d, err := RandomScalar()
	if err != nil {
		return WalletKey{}, err
	}
	P, err := PrivateToPublic(d)
	if err != nil {
		return WalletKey{}, err
	}
	pub, err := PublicKeyHex(P)
	if err != nil {
		return WalletKey{}, err
	}
	addr, err := AddressFromPublicKeyHex(pub)
	if err != nil {
		return WalletKey{}, err
	}
	k := WalletKey{Address: addr, PrivHex: PrivateKeyHex(d), PubHex: pub, Created: time.Now().Unix()}
	w.Keys = append(w.Keys, k)
	if err := n.Save(); err != nil {
		return WalletKey{}, err
	}
	return k, nil
}

func (n *Node) walletAddresses(w *Wallet) map[string]WalletKey {
	m := map[string]WalletKey{}
	for _, k := range w.Keys {
		m[k.Address] = k
	}
	return m
}

func (n *Node) Balance() (int64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	w, err := n.activeWallet()
	if err != nil {
		return 0, err
	}
	addrs := n.walletAddresses(w)
	var bal int64
	height := n.Height()
	for _, u := range n.State.UTXO {
		if _, ok := addrs[u.Address]; ok && n.isMature(u, height) {
			bal += u.Value
		}
	}
	return bal, nil
}

func (n *Node) ListUnspent() ([]UTXO, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	w, err := n.activeWallet()
	if err != nil {
		return nil, err
	}
	addrs := n.walletAddresses(w)
	var out []UTXO
	height := n.Height()
	for _, u := range n.State.UTXO {
		if _, ok := addrs[u.Address]; ok && n.isMature(u, height) {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Height == out[j].Height {
			return out[i].TxID < out[j].TxID
		}
		return out[i].Height < out[j].Height
	})
	return out, nil
}

func (n *Node) isMature(u UTXO, height int) bool {
	if !u.Coinbase {
		return true
	}
	return height-u.Height+1 >= CoinbaseMaturity
}

func (n *Node) MineBlocks(count int, address string) ([]Block, error) {
	if count <= 0 {
		return nil, errors.New("count must be positive")
	}
	if !VerifyAddress(address) {
		return nil, errors.New("invalid toy address")
	}
	var mined []Block
	for i := 0; i < count; i++ {
		n.mu.Lock()
		txs := []Transaction{CoinbaseTx(address, DefaultReward, n.Height()+1, "Toycoin Core coinbase")}
		txs = append(txs, n.State.Mempool...)
		prev := n.Tip()
		b := Block{Header: BlockHeader{Version: 1, PrevHash: prev.Hash, Time: time.Now().Unix(), Bits: DefaultBits, Height: n.Height() + 1}, Tx: txs}
		for ti := range b.Tx {
			b.Tx[ti].TxID = b.Tx[ti].ComputeTxID()
		}
		b.Header.MerkleRoot = MerkleRoot(b.Tx)
		n.mu.Unlock()
		for nonce := uint64(0); ; nonce++ {
			b.Header.Nonce = nonce
			h := b.Header.Hash()
			if MeetsTarget(h, b.Header.Bits) {
				b.Hash = h
				break
			}
		}
		n.mu.Lock()
		if err := n.applyBlockLocked(b, true); err != nil {
			n.mu.Unlock()
			return mined, err
		}
		n.State.Mempool = []Transaction{}
		if err := n.Save(); err != nil {
			n.mu.Unlock()
			return mined, err
		}
		n.mu.Unlock()
		mined = append(mined, b)
		go n.broadcastBlock(b)
	}
	return mined, nil
}

func (n *Node) CreateSendTx(to string, amount int64) (Transaction, error) {
	if !VerifyAddress(to) {
		return Transaction{}, errors.New("invalid destination address")
	}
	if amount <= 0 {
		return Transaction{}, errors.New("amount must be positive")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	w, err := n.activeWallet()
	if err != nil {
		return Transaction{}, err
	}
	addrs := n.walletAddresses(w)
	height := n.Height()
	var inputs []TxIn
	var total int64
	keyForInput := map[string]WalletKey{}
	for _, u := range n.State.UTXO {
		if k, ok := addrs[u.Address]; ok && n.isMature(u, height) {
			inputs = append(inputs, TxIn{PrevTxID: u.TxID, Vout: u.Vout, PubKey: k.PubHex})
			total += u.Value
			keyForInput[UTXOKey(u.TxID, u.Vout)] = k
		}
	}
	if len(inputs) == 0 {
		return Transaction{}, errors.New("wallet has no spendable UTXO")
	}
	fee := DefaultFee
	if total < amount+fee {
		return Transaction{}, fmt.Errorf("insufficient funds: have %s need %s + fee %s", FormatAmount(total), FormatAmount(amount), FormatAmount(fee))
	}
	change := total - amount - fee
	// Sweep model: spend every available wallet UTXO and send change to a fresh address.
	changeAddr := ""
	var outputs []TxOut
	outputs = append(outputs, TxOut{Value: amount, Address: to})
	if change > 0 {
		d, err := RandomScalar()
		if err != nil {
			return Transaction{}, err
		}
		P, err := PrivateToPublic(d)
		if err != nil {
			return Transaction{}, err
		}
		pub, err := PublicKeyHex(P)
		if err != nil {
			return Transaction{}, err
		}
		addr, err := AddressFromPublicKeyHex(pub)
		if err != nil {
			return Transaction{}, err
		}
		k := WalletKey{Address: addr, PrivHex: PrivateKeyHex(d), PubHex: pub, Created: time.Now().Unix()}
		w.Keys = append(w.Keys, k)
		changeAddr = addr
		outputs = append(outputs, TxOut{Value: change, Address: addr})
	}
	tx := Transaction{Version: 1, Vin: inputs, Vout: outputs, Locktime: 0}
	sighash := tx.SigningHash()
	for i := range tx.Vin {
		key := keyForInput[UTXOKey(tx.Vin[i].PrevTxID, tx.Vin[i].Vout)]
		d, err := ParsePrivateKeyHex(key.PrivHex)
		if err != nil {
			return Transaction{}, err
		}
		sig, err := Sign(sighash, d)
		if err != nil {
			return Transaction{}, err
		}
		tx.Vin[i].Signature = sig
	}
	tx.TxID = tx.ComputeTxID()
	if err := n.validateTxLocked(tx, false); err != nil {
		return Transaction{}, err
	}
	n.State.Mempool = append(n.State.Mempool, tx)
	n.State.Meta["last_change_address"] = changeAddr
	if err := n.Save(); err != nil {
		return Transaction{}, err
	}
	go n.broadcastTx(tx)
	return tx, nil
}

func (n *Node) validateTxLocked(tx Transaction, coinbaseAllowed bool) error {
	if tx.IsCoinbase() {
		if !coinbaseAllowed {
			return errors.New("coinbase not allowed here")
		}
		return nil
	}
	seen := map[string]bool{}
	var inSum int64
	sighash := tx.SigningHash()
	for _, vin := range tx.Vin {
		key := UTXOKey(vin.PrevTxID, vin.Vout)
		if seen[key] {
			return errors.New("duplicate input")
		}
		seen[key] = true
		u, ok := n.State.UTXO[key]
		if !ok {
			return fmt.Errorf("missing utxo %s", key)
		}
		pub, err := ParsePublicKeyHex(vin.PubKey)
		if err != nil {
			return err
		}
		addr, err := AddressFromPublicKeyHex(vin.PubKey)
		if err != nil {
			return err
		}
		if addr != u.Address {
			return errors.New("pubkey does not match utxo address")
		}
		if !Verify(sighash, vin.Signature, pub) {
			return errors.New("bad signature")
		}
		inSum += u.Value
	}
	var outSum int64
	for _, vout := range tx.Vout {
		if vout.Value <= 0 {
			return errors.New("non-positive output")
		}
		if !VerifyAddress(vout.Address) {
			return errors.New("invalid output address")
		}
		outSum += vout.Value
	}
	if outSum > inSum {
		return errors.New("outputs exceed inputs")
	}
	return nil
}

func (n *Node) applyBlockLocked(b Block, fromLocalMining bool) error {
	tip := n.Tip()
	if b.Header.Height != tip.Header.Height+1 {
		return fmt.Errorf("bad height: got %d want %d", b.Header.Height, tip.Header.Height+1)
	}
	if b.Header.PrevHash != tip.Hash {
		return errors.New("bad prev hash")
	}
	if b.Header.MerkleRoot != MerkleRoot(b.Tx) {
		return errors.New("bad merkle root")
	}
	if b.Hash == "" {
		b.Hash = b.Header.Hash()
	}
	if b.Header.Hash() != b.Hash {
		return errors.New("bad block hash")
	}
	if !MeetsTarget(b.Hash, b.Header.Bits) {
		return errors.New("proof of work target not met")
	}
	if len(b.Tx) == 0 || !b.Tx[0].IsCoinbase() {
		return errors.New("first tx must be coinbase")
	}
	working := cloneUTXO(n.State.UTXO)
	old := n.State.UTXO
	n.State.UTXO = working
	for i, tx := range b.Tx {
		if tx.TxID == "" {
			tx.TxID = tx.ComputeTxID()
		}
		if i == 0 {
			if !tx.IsCoinbase() {
				n.State.UTXO = old
				return errors.New("bad coinbase")
			}
		} else if err := n.validateTxLocked(tx, false); err != nil {
			n.State.UTXO = old
			return fmt.Errorf("tx %s invalid: %w", tx.TxID, err)
		}
		if !tx.IsCoinbase() {
			for _, vin := range tx.Vin {
				delete(n.State.UTXO, UTXOKey(vin.PrevTxID, vin.Vout))
			}
		}
		for vout, out := range tx.Vout {
			if out.Value > 0 && VerifyAddress(out.Address) {
				n.State.UTXO[UTXOKey(tx.TxID, vout)] = UTXO{TxID: tx.TxID, Vout: vout, Value: out.Value, Address: out.Address, Height: b.Header.Height, Coinbase: tx.IsCoinbase()}
			}
		}
	}
	n.State.Blocks = append(n.State.Blocks, b)
	// Remove confirmed txs from mempool.
	confirmed := map[string]bool{}
	for _, tx := range b.Tx {
		confirmed[tx.TxID] = true
	}
	var mp []Transaction
	for _, tx := range n.State.Mempool {
		if !confirmed[tx.TxID] {
			mp = append(mp, tx)
		}
	}
	n.State.Mempool = mp
	return nil
}

func cloneUTXO(m map[string]UTXO) map[string]UTXO {
	out := make(map[string]UTXO, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (n *Node) SubmitBlock(b Block) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.applyBlockLocked(b, false); err != nil {
		return err
	}
	return n.Save()
}

func (n *Node) SubmitTx(tx Transaction) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if tx.TxID == "" {
		tx.TxID = tx.ComputeTxID()
	}
	for _, t := range n.State.Mempool {
		if t.TxID == tx.TxID {
			return nil
		}
	}
	if err := n.validateTxLocked(tx, false); err != nil {
		return err
	}
	n.State.Mempool = append(n.State.Mempool, tx)
	return n.Save()
}

func (n *Node) WalletReport() map[string]interface{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	exposed := map[string]bool{}
	for _, b := range n.State.Blocks {
		for _, tx := range b.Tx {
			for _, vin := range tx.Vin {
				if vin.PubKey != "" {
					if addr, err := AddressFromPublicKeyHex(vin.PubKey); err == nil {
						exposed[addr] = true
					}
				}
			}
		}
	}
	risky := []map[string]interface{}{}
	safeExposedEmpty := 0
	for addr := range exposed {
		var bal int64
		for _, u := range n.State.UTXO {
			if u.Address == addr {
				bal += u.Value
			}
		}
		if bal > 0 {
			risky = append(risky, map[string]interface{}{"address": addr, "balance": FormatAmount(bal), "risk": "pubkey_exposed_with_unspent_balance"})
		} else {
			safeExposedEmpty++
		}
	}
	return map[string]interface{}{
		"exposed_addresses":       len(exposed),
		"exposed_empty_addresses": safeExposedEmpty,
		"risky_addresses":         risky,
		"lesson":                  "A public key revealed by a spend is safe only if no UTXO remains on that same address. Toycoin wallet uses sweep + fresh change by default.",
	}
}

func (n *Node) ChainInfo() map[string]interface{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	tip := n.Tip()
	return map[string]interface{}{
		"chain":                              NetworkName,
		"blocks":                             n.Height(),
		"bestblockhash":                      tip.Hash,
		"difficulty_bits_leading_hex_zeroes": tip.Header.Bits,
		"mempool_tx":                         len(n.State.Mempool),
		"utxo_count":                         len(n.State.UTXO),
		"curve":                              "toy128k1f",
		"curve_order_hex":                    fmt.Sprintf("%x", CurveN),
		"kangaroo_generic_cost":              "~2^64 group operations",
		"address_format":                     "Bech32 witness-v0: tn1q... (HRP=tn, program=ToyHash160(pubkey))",
	}
}

func (n *Node) GetBlockHash(height int) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if height < 0 || height >= len(n.State.Blocks) {
		return "", errors.New("height out of range")
	}
	return n.State.Blocks[height].Hash, nil
}

func (n *Node) GetBlock(hash string) (Block, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, b := range n.State.Blocks {
		if b.Hash == hash {
			return b, nil
		}
	}
	return Block{}, errors.New("block not found")
}

func (n *Node) SyncLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.SyncOnce()
		case <-stop:
			return
		}
	}
}

func (n *Node) SyncOnce() {
	for _, peer := range n.Peers {
		info, err := rpcCallMap(peer, "getblockchaininfo", []interface{}{})
		if err != nil {
			continue
		}
		remoteBlocks, ok := asInt(info["blocks"])
		if !ok {
			continue
		}
		for {
			n.mu.Lock()
			local := n.Height()
			n.mu.Unlock()
			if local >= remoteBlocks {
				break
			}
			h, err := rpcCallString(peer, "getblockhash", []interface{}{local + 1})
			if err != nil {
				break
			}
			br, err := rpcCallBlock(peer, "getblock", []interface{}{h})
			if err != nil {
				break
			}
			if err := n.SubmitBlock(br); err != nil {
				break
			}
		}
	}
}

func (n *Node) broadcastTx(tx Transaction) {
	for _, p := range n.Peers {
		_, _ = rpcPost(p, "submittransaction", []interface{}{tx})
	}
}
func (n *Node) broadcastBlock(b Block) {
	for _, p := range n.Peers {
		_, _ = rpcPost(p, "submitblock", []interface{}{b})
	}
}

func rpcPost(base, method string, params []interface{}) (json.RawMessage, error) {
	req := map[string]interface{}{"method": method, "params": params}
	body, _ := json.Marshal(req)
	resp, err := http.Post(strings.TrimRight(base, "/")+"/rpc", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var r struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if r.Error != "" {
		return nil, errors.New(r.Error)
	}
	return r.Result, nil
}
func rpcCallMap(peer, method string, params []interface{}) (map[string]interface{}, error) {
	raw, err := rpcPost(peer, method, params)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	return m, json.Unmarshal(raw, &m)
}
func rpcCallString(peer, method string, params []interface{}) (string, error) {
	raw, err := rpcPost(peer, method, params)
	if err != nil {
		return "", err
	}
	var s string
	return s, json.Unmarshal(raw, &s)
}
func rpcCallBlock(peer, method string, params []interface{}) (Block, error) {
	raw, err := rpcPost(peer, method, params)
	if err != nil {
		return Block{}, err
	}
	var b Block
	return b, json.Unmarshal(raw, &b)
}
func asInt(v interface{}) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case int:
		return t, true
	default:
		return 0, false
	}
}

func (n *Node) RPCHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || r.URL.Path == "/explorer" {
		n.explorer(w, r)
		return
	}
	if r.URL.Path != "/rpc" {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRPC(w, nil, err)
		return
	}
	res, err := n.handleRPC(req.Method, req.Params)
	writeRPC(w, res, err)
}

func writeRPC(w http.ResponseWriter, result interface{}, err error) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{"result": result, "error": ""}
	if err != nil {
		resp["error"] = err.Error()
		resp["result"] = nil
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func paramString(params []json.RawMessage, i int) (string, error) {
	if len(params) <= i {
		return "", errors.New("missing parameter")
	}
	var s string
	if err := json.Unmarshal(params[i], &s); err != nil {
		return "", err
	}
	return s, nil
}
func paramInt(params []json.RawMessage, i int) (int, error) {
	if len(params) <= i {
		return 0, errors.New("missing parameter")
	}
	var n int
	if err := json.Unmarshal(params[i], &n); err != nil {
		var f float64
		if e := json.Unmarshal(params[i], &f); e != nil {
			return 0, err
		}
		n = int(f)
	}
	return n, nil
}
func paramTx(params []json.RawMessage, i int) (Transaction, error) {
	if len(params) <= i {
		return Transaction{}, errors.New("missing parameter")
	}
	var tx Transaction
	return tx, json.Unmarshal(params[i], &tx)
}
func paramBlock(params []json.RawMessage, i int) (Block, error) {
	if len(params) <= i {
		return Block{}, errors.New("missing parameter")
	}
	var b Block
	return b, json.Unmarshal(params[i], &b)
}

func (n *Node) handleRPC(method string, params []json.RawMessage) (interface{}, error) {
	switch strings.ToLower(method) {
	case "getblockchaininfo":
		return n.ChainInfo(), nil
	case "getnetworkinfo":
		return map[string]interface{}{"network": NetworkName, "version": "0.1.2", "p2p_port": DefaultP2PPort, "rpc_port": DefaultRPCPort, "peers": n.Peers, "address_format": "tn1q... Bech32 witness-v0"}, nil
	case "getpeerinfo":
		return n.Peers, nil
	case "createwallet":
		name, err := paramString(params, 0)
		if err != nil {
			return nil, err
		}
		return n.CreateWallet(name)
	case "getnewaddress":
		k, err := n.GetNewAddress()
		if err != nil {
			return nil, err
		}
		return k.Address, nil
	case "getbalance":
		b, err := n.Balance()
		if err != nil {
			return nil, err
		}
		return FormatAmount(b), nil
	case "listunspent":
		return n.ListUnspent()
	case "dumpprivkey":
		addr, err := paramString(params, 0)
		if err != nil {
			return nil, err
		}
		return n.dumpPrivKey(addr)
	case "generatetoaddress":
		c, err := paramInt(params, 0)
		if err != nil {
			return nil, err
		}
		addr, err := paramString(params, 1)
		if err != nil {
			return nil, err
		}
		return n.MineBlocks(c, addr)
	case "sendtoaddress":
		addr, err := paramString(params, 0)
		if err != nil {
			return nil, err
		}
		amtS, err := paramString(params, 1)
		if err != nil {
			return nil, err
		}
		amt, err := ParseAmount(amtS)
		if err != nil {
			return nil, err
		}
		tx, err := n.CreateSendTx(addr, amt)
		if err != nil {
			return nil, err
		}
		return tx.TxID, nil
	case "getrawmempool":
		n.mu.Lock()
		defer n.mu.Unlock()
		ids := []string{}
		for _, tx := range n.State.Mempool {
			ids = append(ids, tx.TxID)
		}
		return ids, nil
	case "getblockcount":
		return n.Height(), nil
	case "getbestblockhash":
		return n.Tip().Hash, nil
	case "getblockhash":
		h, err := paramInt(params, 0)
		if err != nil {
			return nil, err
		}
		return n.GetBlockHash(h)
	case "getblock":
		hash, err := paramString(params, 0)
		if err != nil {
			return nil, err
		}
		return n.GetBlock(hash)
	case "submitblock":
		b, err := paramBlock(params, 0)
		if err != nil {
			return nil, err
		}
		return "accepted", n.SubmitBlock(b)
	case "submittransaction":
		tx, err := paramTx(params, 0)
		if err != nil {
			return nil, err
		}
		return "accepted", n.SubmitTx(tx)
	case "security.walletreport", "security walletreport", "walletreport":
		return n.WalletReport(), nil
	case "curveinfo":
		return map[string]interface{}{"name": "toy128k1f", "p": fmt.Sprintf("%x", CurveP), "a": CurveA.String(), "b": CurveB.String(), "gx": fmt.Sprintf("%x", CurveGx), "gy": fmt.Sprintf("%x", CurveGy), "n": fmt.Sprintf("%x", CurveN), "h": 1, "seed": "Toy128k1f for Toycoin Core educational network 2026", "address_format": "tn1q... Bech32 witness-v0, HRP=tn"}, nil
	case "validateaddress":
		addr, err := paramString(params, 0)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"isvalid": VerifyAddress(addr), "address": addr}, nil
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}

func (n *Node) dumpPrivKey(addr string) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	w, err := n.activeWallet()
	if err != nil {
		return "", err
	}
	for _, k := range w.Keys {
		if k.Address == addr {
			return PrivKeyPrefix + k.PrivHex, nil
		}
	}
	return "", errors.New("address not in active wallet")
}

func (n *Node) explorer(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tip := n.Tip()
	fmt.Fprintf(w, "<html><body><h1>Toynet128 Explorer</h1><p>Height: %d</p><p>Best: %s</p><p>Mempool: %d tx</p><p>UTXO: %d</p><h2>Latest blocks</h2><table border=1><tr><th>Height</th><th>Hash</th><th>Tx</th></tr>", n.Height(), tip.Hash, len(n.State.Mempool), len(n.State.UTXO))
	start := len(n.State.Blocks) - 10
	if start < 0 {
		start = 0
	}
	for i := len(n.State.Blocks) - 1; i >= start; i-- {
		b := n.State.Blocks[i]
		fmt.Fprintf(w, "<tr><td>%d</td><td><code>%s</code></td><td>%d</td></tr>", b.Header.Height, b.Hash, len(b.Tx))
	}
	fmt.Fprint(w, "</table></body></html>")
}

func (n *Node) ExportRawState() []byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	b, _ := json.MarshalIndent(n.State, "", "  ")
	return b
}

func BigIntFromDecimal(s string) (*big.Int, error) {
	x, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, errors.New("bad integer")
	}
	return x, nil
}
