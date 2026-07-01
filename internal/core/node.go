package core

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// CookieUser is the fixed username for cookie-file auth, like Bitcoin Core's
// "__cookie__".
const CookieUser = "__cookie__"

// CookieFile is the name of the auth cookie written into the data directory.
const CookieFile = ".cookie"

type Node struct {
	mu        sync.Mutex
	State     *State
	DataDir   string
	StateFile string
	Peers     []string
	// RPC auth credentials. Filled by LoadNode; when DisableAuth is true the
	// /rpc endpoint accepts unauthenticated requests (legacy/tests only).
	rpcUser     string
	rpcPass     string
	cookiePath  string
	DisableAuth bool
	// AuthorityPubKey, when set, is the toy128k1f public key (04-prefixed hex)
	// whose signed checkpoints this node trusts. Empty means checkpoints are
	// disabled and fork choice is pure most-work. Set from -authoritypubkey.
	AuthorityPubKey string
	// SelfURL is this node's own reachable RPC base URL, advertised to peers so
	// they can pull announced items (getblock/gettx). Empty means "not reachable
	// for inbound pulls": the node then relays by pushing full data instead of
	// announcing inventory. Set from -externaladdr.
	SelfURL string
}

// MaxPeers caps how many peers a node will track, so peer-address learning from
// gossip cannot grow the set without bound.
const MaxPeers = 32

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
		// Backfill the block index for states written before fork choice existed.
		if st.Index == nil {
			st.Index = map[string]Block{}
		}
		for _, b := range st.Blocks {
			if _, ok := st.Index[b.Hash]; !ok {
				st.Index[b.Hash] = b
			}
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
	if err := n.setupAuth(); err != nil {
		return nil, err
	}
	if err := n.Save(); err != nil {
		return nil, err
	}
	return n, nil
}

// setupAuth generates fresh cookie credentials for this run and writes them to
// DataDir/.cookie (0600). The cookie is regenerated on every startup, so a
// leaked old cookie is useless once the node restarts.
func (n *Node) setupAuth() error {
	n.cookiePath = filepath.Join(n.DataDir, CookieFile)
	pass, err := randomCookieSecret()
	if err != nil {
		return err
	}
	n.rpcUser = CookieUser
	n.rpcPass = pass
	return writeCookie(n.cookiePath, n.rpcUser, n.rpcPass)
}

func writeCookie(path, user, pass string) error {
	content := []byte(user + ":" + pass)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// randomCookieSecret returns a 32-byte hex-encoded secret (256 bits).
func randomCookieSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ReadCookieFile reads "user:pass" from the cookie file at the given path.
// Returns an error if the file is missing or malformed.
func ReadCookieFile(path string) (user, pass string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(strings.TrimSpace(string(raw)), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errors.New("malformed cookie file")
	}
	return parts[0], parts[1], nil
}

// checkRPCAuth reports whether the request presents valid Basic credentials.
// Always returns false when DisableAuth is false and credentials are absent or
// wrong. Constant-time comparison is used for the password.
func (n *Node) checkRPCAuth(r *http.Request) bool {
	if n.DisableAuth {
		return true
	}
	u, p, ok := r.BasicAuth()
	if !ok || u != n.rpcUser {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(p), []byte(n.rpcPass)) == 1
}

// isLoopback reports whether the request originated from the local machine.
// Used to restrict sensitive calls (dumpprivkey) to loopback regardless of auth.
func isLoopback(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// normalizePeerURL trims a peer address and ensures it has an http(s) scheme.
// Returns "" for empty input.
func normalizePeerURL(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "http://") && !strings.HasPrefix(p, "https://") {
		p = "http://" + p
	}
	return p
}

func mergePeers(a, b []string) []string {
	m := map[string]bool{}
	var out []string
	for _, p := range append(a, b...) {
		p = normalizePeerURL(p)
		if p == "" {
			continue
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
		// Miner collects fees: the coinbase pays the block subsidy plus the
		// total fees of the mempool txs included in this block, like Bitcoin.
		var totalFees int64
		for _, mtx := range n.State.Mempool {
			totalFees += n.txFeeLocked(mtx)
		}
		txs := []Transaction{CoinbaseTx(address, DefaultReward+totalFees, n.Height()+1, "Toycoin Core coinbase")}
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
		// While we held no lock during PoW, a block received via sync may have
		// advanced the tip. Our mined block was built on the old prev hash, so
		// it would now be rejected as "bad prev hash". Detect that case and just
		// skip this mined block, continuing to the next iteration where we will
		// rebuild on top of the new tip — instead of bailing out with an error
		// that makes the caller think mining failed.
		if n.Tip().Hash != b.Header.PrevHash {
			n.mu.Unlock()
			continue
		}
		if err := n.acceptBlockLocked(b); err != nil {
			n.mu.Unlock()
			return mined, err
		}
		// acceptBlockLocked already drops the mempool txs that this block
		// confirmed; any tx that arrived during PoW and was not included stays.
		if err := n.Save(); err != nil {
			n.mu.Unlock()
			return mined, err
		}
		n.mu.Unlock()
		mined = append(mined, b)
		go n.relayInv([]InvItem{{Type: InvBlock, Hash: b.Hash}}, "")
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
	go n.relayInv([]InvItem{{Type: InvTx, Hash: tx.TxID}}, "")
	return tx, nil
}

// txFee returns sum(inputs) - sum(outputs) for a non-coinbase tx, evaluated
// against the given UTXO set. Inputs referencing missing UTXOs are treated as
// zero value (consistent with validateTx rejecting them).
func txFee(tx Transaction, utxo map[string]UTXO) int64 {
	if tx.IsCoinbase() {
		return 0
	}
	var inSum, outSum int64
	for _, vin := range tx.Vin {
		if u, ok := utxo[UTXOKey(vin.PrevTxID, vin.Vout)]; ok {
			inSum += u.Value
		}
	}
	for _, vout := range tx.Vout {
		outSum += vout.Value
	}
	return inSum - outSum
}

// txFeeLocked evaluates txFee against the active-chain UTXO set. Caller holds n.mu.
func (n *Node) txFeeLocked(tx Transaction) int64 { return txFee(tx, n.State.UTXO) }

// validateTxLocked validates a tx against the active-chain UTXO set. Caller holds n.mu.
func (n *Node) validateTxLocked(tx Transaction, coinbaseAllowed bool) error {
	return validateTx(tx, n.State.UTXO, coinbaseAllowed)
}

// validateTx checks a transaction against the supplied UTXO set. It is a free
// function (no node state) so it can validate txs on a candidate fork branch
// during a reorg, not just on the active chain.
func validateTx(tx Transaction, utxo map[string]UTXO, coinbaseAllowed bool) error {
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
		u, ok := utxo[key]
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

// connectBlock validates block b as the child of prev and, if valid, applies it
// to the given UTXO set (mutated in place). It has no access to node state, so
// the same routine validates the active tip, a freshly mined block, and any
// candidate fork branch replayed during a reorg. On error the utxo map may be
// partially mutated, so callers must pass a throwaway copy.
func connectBlock(b Block, prev Block, utxo map[string]UTXO) error {
	if b.Header.Height != prev.Header.Height+1 {
		return fmt.Errorf("bad height: got %d want %d", b.Header.Height, prev.Header.Height+1)
	}
	if b.Header.PrevHash != prev.Hash {
		return errors.New("bad prev hash")
	}
	// Reject blocks timestamped implausibly far in the future. There is
	// intentionally no median-time-past check and no difficulty retarget here:
	// this is an educational chain with a fixed target, and those consensus
	// rules are left out on purpose to keep the code readable.
	if b.Header.Time > time.Now().Unix()+MaxFutureBlockTime {
		return errors.New("block timestamp too far in the future")
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
	// totalFees accumulates sum(inputs)-sum(outputs) across the block's
	// non-coinbase txs, computed against the UTXO set as it exists at each tx
	// (so a tx spending an earlier tx's output in the same block is handled).
	var totalFees int64
	for i, tx := range b.Tx {
		if tx.TxID == "" {
			tx.TxID = tx.ComputeTxID()
		}
		if i == 0 {
			if !tx.IsCoinbase() {
				return errors.New("bad coinbase")
			}
		} else {
			if tx.IsCoinbase() {
				return errors.New("only the first tx may be a coinbase")
			}
			if err := validateTx(tx, utxo, false); err != nil {
				return fmt.Errorf("tx %s invalid: %w", tx.TxID, err)
			}
		}
		if !tx.IsCoinbase() {
			// txFee reads utxo before we delete this tx's inputs below, so inSum
			// is correct even for a tx spending an earlier tx in the same block.
			totalFees += txFee(tx, utxo)
			for _, vin := range tx.Vin {
				delete(utxo, UTXOKey(vin.PrevTxID, vin.Vout))
			}
		}
		for vout, out := range tx.Vout {
			if out.Value > 0 && VerifyAddress(out.Address) {
				utxo[UTXOKey(tx.TxID, vout)] = UTXO{TxID: tx.TxID, Vout: vout, Value: out.Value, Address: out.Address, Height: b.Header.Height, Coinbase: tx.IsCoinbase()}
			}
		}
	}
	// Enforce the emission rule: the coinbase may pay at most the block subsidy
	// plus the fees actually collected from the block's transactions. Without
	// this check a peer could submit a block whose coinbase mints coins out of
	// thin air (unbounded inflation) — the exact failure Toycoin is meant to
	// teach against.
	var coinbaseOut int64
	for _, out := range b.Tx[0].Vout {
		coinbaseOut += out.Value
	}
	if coinbaseOut > DefaultReward+totalFees {
		return fmt.Errorf("coinbase pays %s but max allowed is %s (subsidy %s + fees %s)",
			FormatAmount(coinbaseOut), FormatAmount(DefaultReward+totalFees), FormatAmount(DefaultReward), FormatAmount(totalFees))
	}
	return nil
}

// acceptBlockLocked is the single entry point for every block, whether mined
// locally or received from a peer. It validates the block's proof of work and
// self-consistency, records it in the block index, and then either extends the
// active chain directly (fast path) or, if the block belongs to a side branch,
// runs fork choice to switch onto the most-work chain. Caller holds n.mu.
func (n *Node) acceptBlockLocked(b Block) error {
	if b.Hash == "" {
		b.Hash = b.Header.Hash()
	}
	if b.Header.Hash() != b.Hash {
		return errors.New("bad block hash")
	}
	if !MeetsTarget(b.Hash, b.Header.Bits) {
		return errors.New("proof of work target not met")
	}
	// Populate txids so the stored block, its merkle root and getblock all agree.
	for i := range b.Tx {
		if b.Tx[i].TxID == "" {
			b.Tx[i].TxID = b.Tx[i].ComputeTxID()
		}
	}
	if len(b.Tx) == 0 || !b.Tx[0].IsCoinbase() {
		return errors.New("first tx must be coinbase")
	}
	if b.Header.MerkleRoot != MerkleRoot(b.Tx) {
		return errors.New("bad merkle root")
	}
	if _, known := n.State.Index[b.Hash]; known {
		return nil // already have it; accepting again is a no-op
	}

	tip := n.Tip()
	// Fast path only when the block extends the active tip AND that active chain
	// already honors any checkpoint (so appending cannot bless a forbidden
	// branch). If the active chain is currently in violation — e.g. a checkpoint
	// just arrived for a branch we have not synced yet — fall through to reorg,
	// which only ever adopts checkpoint-honoring chains.
	if b.Header.PrevHash == tip.Hash && b.Header.Height == tip.Header.Height+1 && n.chainHonorsCheckpointLocked(n.State.Blocks) {
		// Validate against a copy of the UTXO set so a failure leaves state
		// untouched, then commit.
		working := cloneUTXO(n.State.UTXO)
		if err := connectBlock(b, tip, working); err != nil {
			return err
		}
		n.State.UTXO = working
		n.State.Blocks = append(n.State.Blocks, b)
		n.State.Index[b.Hash] = b
		n.removeConfirmedFromMempoolLocked(b.Tx)
		return nil
	}

	// The block does not extend the active tip: it is a fork or an orphan whose
	// parent we may already have. Store it and let fork choice decide whether the
	// branch it belongs to now outweighs the active chain.
	n.State.Index[b.Hash] = b
	n.reorgToBestLocked()
	return nil
}

// chainHonorsCheckpointLocked reports whether a genesis-first chain contains the
// currently accepted checkpoint's block at the checkpoint height. With no
// checkpoint set, every chain honors it.
func (n *Node) chainHonorsCheckpointLocked(chain []Block) bool {
	cp := n.State.Checkpoint
	if cp == nil {
		return true
	}
	if cp.Height < 0 || cp.Height >= len(chain) {
		return false // chain does not even reach the checkpoint height
	}
	return chain[cp.Height].Hash == cp.BlockHash
}

// reorgToBestLocked scans the block index for the valid, checkpoint-honoring
// chain with the most cumulative work and makes it active, rebuilding the UTXO
// set and mempool. A checkpoint acts as a veto: chains that do not contain the
// checkpointed block are never adopted, no matter how much work they carry.
//
// Ties keep the incumbent chain, so the node does not flap between equal
// branches. The one exception is when the active chain itself violates a
// (newly arrived) checkpoint: then any honoring chain is preferable, even a
// lighter one, so the node leaves the forbidden branch as soon as it can.
func (n *Node) reorgToBestLocked() {
	activeHonors := n.chainHonorsCheckpointLocked(n.State.Blocks)
	var bestChain []Block
	var bestUTXO map[string]UTXO
	bestWork := big.NewInt(-1)
	if activeHonors {
		bestChain = n.State.Blocks
		bestWork = chainWork(n.State.Blocks)
		// bestUTXO stays nil: "keep the current active chain unless beaten".
	}
	for hash := range n.State.Index {
		chain, ok := n.buildChainLocked(hash)
		if !ok {
			continue
		}
		if !n.chainHonorsCheckpointLocked(chain) {
			continue // vetoed by the checkpoint
		}
		w := chainWork(chain)
		if w.Cmp(bestWork) <= 0 {
			continue
		}
		utxo, err := replayChain(chain)
		if err != nil {
			continue // this branch contains an invalid block; ignore it
		}
		bestChain, bestWork, bestUTXO = chain, w, utxo
	}
	if bestUTXO == nil {
		if !activeHonors {
			cp := n.State.Checkpoint
			log.Printf("[CHECKPOINT] active chain violates checkpoint (height=%d hash=%s) and no honoring chain is known yet; waiting for sync", cp.Height, cp.BlockHash)
		}
		return // nothing better (or nothing honoring) to switch to
	}
	oldChain := n.State.Blocks
	n.State.Blocks = bestChain
	n.State.UTXO = bestUTXO
	n.rebuildMempoolAfterReorgLocked(oldChain, bestChain)
	newTip := bestChain[len(bestChain)-1]
	log.Printf("[REORG] active chain switched to tip=%s height=%d (old height=%d)", newTip.Hash, newTip.Header.Height, oldChain[len(oldChain)-1].Header.Height)
}

// buildChainLocked reconstructs the chain from genesis up to the block `hash`
// by following prev-hash links through the index. It returns false if any
// ancestor is missing or the branch does not anchor to our genesis block.
func (n *Node) buildChainLocked(hash string) ([]Block, bool) {
	genesisHash := n.State.Blocks[0].Hash
	var rev []Block
	h := hash
	for i := 0; i <= len(n.State.Index); i++ {
		b, ok := n.State.Index[h]
		if !ok {
			return nil, false
		}
		rev = append(rev, b)
		if b.Hash == genesisHash {
			chain := make([]Block, len(rev))
			for j, blk := range rev {
				chain[len(rev)-1-j] = blk
			}
			return chain, true
		}
		if b.Header.Height == 0 {
			return nil, false // a height-0 block that is not our genesis: foreign chain
		}
		h = b.Header.PrevHash
	}
	return nil, false // chain longer than the index: a cycle, reject it
}

// replayChain validates a full chain (genesis first) into a fresh UTXO set.
// Genesis itself carries no spendable output, so application starts at height 1.
func replayChain(chain []Block) (map[string]UTXO, error) {
	utxo := map[string]UTXO{}
	for i := 1; i < len(chain); i++ {
		if err := connectBlock(chain[i], chain[i-1], utxo); err != nil {
			return nil, err
		}
	}
	return utxo, nil
}

// blockWork is the expected work of a block at the given difficulty. Each
// required leading hex zero multiplies the search space by 16, so work = 16^bits.
func blockWork(bits int) *big.Int {
	if bits < 0 {
		bits = 0
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(4*bits)) // 2^(4*bits) == 16^bits
}

// chainWork sums the per-block work over a chain. With a fixed target this is
// equivalent to counting blocks, but summing work keeps fork choice correct if
// the difficulty ever varies.
func chainWork(chain []Block) *big.Int {
	sum := new(big.Int)
	for _, b := range chain {
		sum.Add(sum, blockWork(b.Header.Bits))
	}
	return sum
}

// removeConfirmedFromMempoolLocked drops any mempool tx now confirmed in a block.
func (n *Node) removeConfirmedFromMempoolLocked(txs []Transaction) {
	confirmed := map[string]bool{}
	for _, tx := range txs {
		confirmed[tx.TxID] = true
	}
	var mp []Transaction
	for _, tx := range n.State.Mempool {
		if !confirmed[tx.TxID] {
			mp = append(mp, tx)
		}
	}
	n.State.Mempool = mp
}

// rebuildMempoolAfterReorgLocked recomputes the mempool after switching chains.
// Non-coinbase txs from blocks that were disconnected (on the old chain but not
// the new one) are returned to the mempool, together with the txs already there,
// minus anything now confirmed on the new chain or no longer valid against the
// new UTXO set. n.State.UTXO must already point at the new chain's UTXO set.
func (n *Node) rebuildMempoolAfterReorgLocked(oldChain, newChain []Block) {
	confirmed := map[string]bool{}
	newHashes := map[string]bool{}
	for _, b := range newChain {
		newHashes[b.Hash] = true
		for _, tx := range b.Tx {
			confirmed[tx.TxID] = true
		}
	}
	candidates := append([]Transaction{}, n.State.Mempool...)
	for _, b := range oldChain {
		if newHashes[b.Hash] {
			continue // block survived the reorg; its txs stay confirmed
		}
		for _, tx := range b.Tx {
			if tx.IsCoinbase() {
				continue // a disconnected coinbase cannot re-enter the mempool
			}
			candidates = append(candidates, tx)
		}
	}
	var mp []Transaction
	seen := map[string]bool{}
	for _, tx := range candidates {
		if tx.TxID == "" {
			tx.TxID = tx.ComputeTxID()
		}
		if confirmed[tx.TxID] || seen[tx.TxID] {
			continue
		}
		if validateTx(tx, n.State.UTXO, false) != nil {
			continue // spent by the winning branch or otherwise no longer valid
		}
		seen[tx.TxID] = true
		mp = append(mp, tx)
	}
	n.State.Mempool = mp
}

// hasBlockLocked reports whether a block with the given hash is in the index.
func (n *Node) hasBlockLocked(hash string) bool {
	_, ok := n.State.Index[hash]
	return ok
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
	if b.Hash == "" {
		b.Hash = b.Header.Hash()
	}
	wasNew := !n.hasBlockLocked(b.Hash)
	err := n.acceptBlockLocked(b)
	if err == nil {
		err = n.Save()
	}
	n.mu.Unlock()
	if err != nil {
		return err
	}
	// Relay a genuinely new block onward for transitive gossip. A peer that
	// already has it will not re-relay, so the flood terminates.
	if wasNew {
		go n.relayInv([]InvItem{{Type: InvBlock, Hash: b.Hash}}, "")
	}
	return nil
}

// SubmitCheckpoint validates an authority-signed checkpoint and, if it is newer
// than the one we hold, records it and re-runs fork choice. A checkpoint can
// force the node off a branch the authority did not bless.
func (n *Node) SubmitCheckpoint(cp Checkpoint) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.AuthorityPubKey == "" {
		return errors.New("this node has no authority key configured; checkpoints are disabled")
	}
	if err := VerifyCheckpoint(cp, n.AuthorityPubKey); err != nil {
		return err
	}
	if n.State.Checkpoint != nil && cp.Height <= n.State.Checkpoint.Height {
		return nil // never downgrade; also stops rebroadcast loops (no push below)
	}
	n.State.Checkpoint = &cp
	n.reorgToBestLocked()
	if err := n.Save(); err != nil {
		return err
	}
	// Relay only genuinely-new checkpoints onward. Peers that already hold this
	// height short-circuit above and do not re-broadcast, so the flood stops.
	go n.broadcastCheckpoint(cp)
	return nil
}

func (n *Node) SubmitTx(tx Transaction) error {
	n.mu.Lock()
	if tx.TxID == "" {
		tx.TxID = tx.ComputeTxID()
	}
	for _, t := range n.State.Mempool {
		if t.TxID == tx.TxID {
			n.mu.Unlock()
			return nil // already have it: do not re-relay (stops gossip loops)
		}
	}
	if err := n.validateTxLocked(tx, false); err != nil {
		n.mu.Unlock()
		return err
	}
	n.State.Mempool = append(n.State.Mempool, tx)
	err := n.Save()
	n.mu.Unlock()
	if err != nil {
		return err
	}
	go n.relayInv([]InvItem{{Type: InvTx, Hash: tx.TxID}}, "")
	return nil
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
	checkpointHeight := -1
	if n.State.Checkpoint != nil {
		checkpointHeight = n.State.Checkpoint.Height
	}
	return map[string]interface{}{
		"chain":                              NetworkName,
		"blocks":                             n.Height(),
		"bestblockhash":                      tip.Hash,
		"chainwork":                          chainWork(n.State.Blocks).String(),
		"known_blocks":                       len(n.State.Index),
		"authority_configured":               n.AuthorityPubKey != "",
		"checkpoint_height":                  checkpointHeight,
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
	// Serve from the full index so peers can pull side-branch blocks announced
	// via inv, not only blocks currently on the active chain.
	if b, ok := n.State.Index[hash]; ok {
		return b, nil
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

// SyncOnce pulls the best chain and the latest checkpoint from each peer.
func (n *Node) SyncOnce() {
	for _, peer := range n.Peers {
		n.syncBlocksFromPeer(peer)
		// Always pull the peer's checkpoint, even when our blocks are already up
		// to date: the authority may have blessed a new tip we must enforce.
		// SubmitCheckpoint no-ops if we have no authority key or it is not newer.
		if cp, ok := rpcGetCheckpoint(peer); ok {
			_ = n.SubmitCheckpoint(cp)
		}
	}
}

// syncBlocksFromPeer walks the peer's chain backward from its best block until
// it reaches a block we already have (the fork point) or genesis, then applies
// those blocks oldest-first. acceptBlockLocked runs fork choice, so if the
// peer's branch carries more work than ours the node reorgs onto it. This makes
// two diverged nodes converge on the heavier chain instead of staying split.
func (n *Node) syncBlocksFromPeer(peer string) {
	info, err := rpcCallMap(peer, "getblockchaininfo", []interface{}{})
	if err != nil {
		return
	}
	remoteHeight, ok := asInt(info["blocks"])
	if !ok {
		return
	}
	remoteTip, _ := info["bestblockhash"].(string)
	if remoteTip == "" {
		return
	}
	n.mu.Lock()
	local := n.Height()
	haveTip := n.hasBlockLocked(remoteTip)
	n.mu.Unlock()
	// With a fixed target, more work == more blocks, so a peer no taller than
	// us can never win fork choice; skip it. Also skip if we already have its
	// tip (nothing new to fetch).
	if haveTip || remoteHeight <= local {
		return
	}
	// Fetch the peer's chain backward from its tip to the first block we know.
	var fetched []Block
	h := remoteTip
	for i := 0; i <= remoteHeight+1; i++ {
		n.mu.Lock()
		known := n.hasBlockLocked(h)
		n.mu.Unlock()
		if known {
			break // reached the common ancestor
		}
		br, err := rpcCallBlock(peer, "getblock", []interface{}{h})
		if err != nil {
			log.Printf("[NET] sync: %s getblock(%s) failed: %v", peer, h, err)
			break
		}
		fetched = append(fetched, br)
		if br.Header.Height == 0 {
			break // reached genesis
		}
		h = br.Header.PrevHash
	}
	// Apply oldest-first so each block's parent is already known.
	for j := len(fetched) - 1; j >= 0; j-- {
		n.mu.Lock()
		err := n.acceptBlockLocked(fetched[j])
		if err == nil {
			err = n.Save()
		}
		n.mu.Unlock()
		if err != nil {
			log.Printf("[NET] sync: %s block %s rejected: %v", peer, fetched[j].Hash, err)
			break
		}
	}
}

func (n *Node) broadcastCheckpoint(cp Checkpoint) {
	for _, p := range n.Peers {
		_, _ = rpcPost(p, "submitcheckpoint", []interface{}{cp})
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
// rpcGetCheckpoint pulls a peer's current checkpoint, if it has one.
func rpcGetCheckpoint(peer string) (Checkpoint, bool) {
	raw, err := rpcPost(peer, "getcheckpoint", []interface{}{})
	if err != nil {
		return Checkpoint{}, false
	}
	var resp struct {
		Checkpoint *Checkpoint `json:"checkpoint"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.Checkpoint == nil {
		return Checkpoint{}, false
	}
	return *resp.Checkpoint, true
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
	// /rpc is a JSON-RPC endpoint; only POST is meaningful here. Rejecting GET
	// etc. avoids logging spurious 405s from browsers/probes and makes the
	// contract explicit.
	if r.Method != http.MethodPost {
		http.Error(w, "405 Method Not Allowed: /rpc requires POST", http.StatusMethodNotAllowed)
		return
	}
	// Cap the request body so a client cannot stream an arbitrarily large JSON
	// blob to exhaust memory. The decoder will error past the limit.
	r.Body = http.MaxBytesReader(w, r.Body, MaxRPCBodyBytes)
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRPC(w, nil, err)
		return
	}
	// Peer sync and the block explorer need to read chain data and push
	// fully-validated blocks/txs/checkpoints without holding this node's private
	// cookie, so those methods are public. Everything that touches wallets, keys
	// or node config still requires cookie auth (and dumpprivkey stays loopback).
	if !isPublicRPCMethod(req.Method) && !n.checkRPCAuth(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="toycoind"`)
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
		return
	}
	res, err := n.handleRPC(req.Method, req.Params, isLoopback(r.RemoteAddr))
	writeRPC(w, res, err)
}

// publicRPCMethods are callable without cookie authentication. They are either
// read-only chain queries (the same data the /explorer page already exposes) or
// consensus-propagation calls whose inputs are fully validated (submitblock,
// submittransaction) or signature-gated (submitcheckpoint). Wallet and key
// operations are deliberately absent and remain authenticated.
var publicRPCMethods = map[string]bool{
	"getblockchaininfo": true,
	"getnetworkinfo":    true,
	"getpeerinfo":       true,
	"getblockcount":     true,
	"getbestblockhash":  true,
	"getblockhash":      true,
	"getblock":          true,
	"getrawmempool":     true,
	"getcheckpoint":     true,
	"gettx":             true,
	"curveinfo":         true,
	"validateaddress":   true,
	"submitblock":       true,
	"submittransaction": true,
	"submitcheckpoint":  true,
	"inv":               true,
}

func isPublicRPCMethod(method string) bool {
	return publicRPCMethods[strings.ToLower(strings.TrimSpace(method))]
}

func writeRPC(w http.ResponseWriter, result interface{}, err error) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{"result": result, "error": ""}
	if err != nil {
		resp["error"] = err.Error()
		resp["result"] = nil
	}
	// If encoding fails mid-write (e.g. a value that cannot be marshalled) the
	// client would receive truncated JSON with no server-side signal. Log it so
	// the operator can see the failure instead of it vanishing silently.
	if encErr := json.NewEncoder(w).Encode(resp); encErr != nil {
		log.Printf("[RPC] failed to encode response: %v", encErr)
	}
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
	// A JSON integer unmarshals cleanly into int. If that fails, also accept a
	// JSON number, but only if it has no fractional part — silently truncating
	// 2.5 into 2 would be a surprising footgun for callers like
	// generatetoaddress/getblockhash.
	var n int
	if err := json.Unmarshal(params[i], &n); err == nil {
		return n, nil
	}
	var f float64
	if err := json.Unmarshal(params[i], &f); err != nil {
		return 0, fmt.Errorf("parameter %d must be an integer", i)
	}
	if f != float64(int64(f)) {
		return 0, fmt.Errorf("parameter %d must be an integer, got %v", i, f)
	}
	return int(f), nil
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
func paramCheckpoint(params []json.RawMessage, i int) (Checkpoint, error) {
	if len(params) <= i {
		return Checkpoint{}, errors.New("missing parameter")
	}
	var cp Checkpoint
	return cp, json.Unmarshal(params[i], &cp)
}
func paramInvItems(params []json.RawMessage, i int) ([]InvItem, error) {
	if len(params) <= i {
		return nil, errors.New("missing parameter")
	}
	var items []InvItem
	return items, json.Unmarshal(params[i], &items)
}

func (n *Node) handleRPC(method string, params []json.RawMessage, loopback bool) (interface{}, error) {
	switch strings.ToLower(method) {
	case "getblockchaininfo":
		return n.ChainInfo(), nil
	case "getrpcinfo":
		authMode := "cookie"
		if n.DisableAuth {
			authMode = "disabled"
		}
		return map[string]interface{}{
			"auth_mode":     authMode,
			"dumpprivkey":   "loopback-only",
			"cookie_path":   n.cookiePath,
			"require_auth":  !n.DisableAuth,
		}, nil
	case "getnetworkinfo":
		return map[string]interface{}{"network": NetworkName, "version": Version, "p2p_port": DefaultP2PPort, "rpc_port": DefaultRPCPort, "peers": n.Peers, "address_format": "tn1q... Bech32 witness-v0"}, nil
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
		// dumpprivkey exports a private key, so it is restricted to loopback
		// connections even when the caller is authenticated. This stops a
		// remote peer with valid cookie creds from draining keys.
		if !loopback {
			return nil, errors.New("dumpprivkey only allowed from loopback (127.0.0.1/::1)")
		}
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
	case "submitcheckpoint":
		cp, err := paramCheckpoint(params, 0)
		if err != nil {
			return nil, err
		}
		return "accepted", n.SubmitCheckpoint(cp)
	case "inv":
		// inv(from, items): a peer announces inventory. from may be "" if the
		// announcer is not reachable for pulls. Handle asynchronously so the
		// announcer's HTTP call returns promptly (getdata happens in the
		// background), mirroring Bitcoin's inv/getdata split.
		from, _ := paramString(params, 0)
		items, err := paramInvItems(params, 1)
		if err != nil {
			return nil, err
		}
		go n.HandleInv(from, items)
		return "ok", nil
	case "gettx":
		txid, err := paramString(params, 0)
		if err != nil {
			return nil, err
		}
		if tx, ok := n.txByHash(txid); ok {
			return tx, nil
		}
		return nil, errors.New("tx not found in mempool")
	case "getcheckpoint":
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.State.Checkpoint == nil {
			return map[string]interface{}{"checkpoint": nil, "authority_configured": n.AuthorityPubKey != ""}, nil
		}
		return map[string]interface{}{"checkpoint": n.State.Checkpoint, "authority_configured": n.AuthorityPubKey != ""}, nil
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
