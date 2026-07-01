package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Merkle root ---

func TestMerkleRootStableAndDeterministic(t *testing.T) {
	makeTxs := func(n int) []Transaction {
		txs := make([]Transaction, n)
		for i := range txs {
			txs[i] = Transaction{Version: 1, TxID: HashHex([]byte{byte('a' + i)})}
		}
		return txs
	}
	for _, n := range []int{0, 1, 2, 3, 5} {
		r1 := MerkleRoot(makeTxs(n))
		r2 := MerkleRoot(makeTxs(n))
		if r1 != r2 {
			t.Fatalf("merkle root not deterministic for n=%d: %q vs %q", n, r1, r2)
		}
		if r1 == "" {
			t.Fatalf("merkle root should be non-empty for n=%d", n)
		}
	}
}

// --- Mining collects fees into the coinbase ---

// newTestNode loads a node with an isolated temp data dir (no real disk state).
func newTestNode(t *testing.T) *Node {
	t.Helper()
	dir := t.TempDir()
	n, err := LoadNode(dir, nil)
	if err != nil {
		t.Fatalf("LoadNode: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return n
}

func TestMinerCollectsFees(t *testing.T) {
	n := newTestNode(t)

	// Wallet A mines initial funds.
	if _, err := n.CreateWallet("miner"); err != nil {
		t.Fatal(err)
	}
	addrA, err := n.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	mined, err := n.MineBlocks(3, addrA.Address)
	if err != nil {
		t.Fatalf("MineBlocks initial: %v", err)
	}
	_ = mined

	// Wallet B to receive a spend and produce a fee.
	if _, err := n.CreateWallet("receiver"); err != nil {
		t.Fatal(err)
	}
	addrB, err := n.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}

	// Switch back to miner wallet and send 10 TOY to B (creates a mempool tx
	// carrying the DefaultFee).
	n.State.ActiveWallet = "miner"
	txid, err := n.CreateSendTx(addrB.Address, 10*Coin)
	if err != nil {
		t.Fatalf("CreateSendTx: %v", err)
	}
	if len(n.State.Mempool) != 1 || n.State.Mempool[0].TxID != txid.TxID {
		t.Fatalf("mempool should contain exactly the new tx")
	}

	// Capture the mempool fee to compare against the coinbase.
	expectedFee := DefaultFee

	// Mine one block. The coinbase must equal subsidy + fee.
	blocks, err := n.MineBlocks(1, addrA.Address)
	if err != nil {
		t.Fatalf("MineBlocks confirm: %v", err)
	}
	last := blocks[len(blocks)-1]
	if len(last.Tx) != 2 {
		t.Fatalf("expected 2 txs (coinbase+spend) in block, got %d", len(last.Tx))
	}
	coinbase := last.Tx[0]
	if !coinbase.IsCoinbase() {
		t.Fatalf("first tx must be coinbase")
	}
	got := coinbase.Vout[0].Value
	want := DefaultReward + expectedFee
	if got != want {
		t.Fatalf("coinbase value = %d, want %d (subsidy %d + fee %d)", got, want, DefaultReward, expectedFee)
	}
	// Mempool must be drained after the block.
	if len(n.State.Mempool) != 0 {
		t.Fatalf("mempool should be empty after mining, has %d", len(n.State.Mempool))
	}
}

func TestMinerNoFeeWhenEmptyMempool(t *testing.T) {
	n := newTestNode(t)
	if _, err := n.CreateWallet("w"); err != nil {
		t.Fatal(err)
	}
	a, err := n.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := n.MineBlocks(1, a.Address)
	if err != nil {
		t.Fatal(err)
	}
	cb := blocks[0].Tx[0]
	if cb.Vout[0].Value != DefaultReward {
		t.Fatalf("coinbase with empty mempool should equal subsidy only: got %d want %d", cb.Vout[0].Value, DefaultReward)
	}
}

// --- applyBlockLocked rollback: an invalid tx must not mutate the UTXO set ---

func TestApplyBlockRollbackOnInvalidTx(t *testing.T) {
	n := newTestNode(t)
	if _, err := n.CreateWallet("w"); err != nil {
		t.Fatal(err)
	}
	a, err := n.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.MineBlocks(2, a.Address); err != nil {
		t.Fatal(err)
	}
	utxoBefore := len(n.State.UTXO)
	heightBefore := n.Height()

	// Build a block at the next height with a second tx that references a
	// non-existent UTXO. applyBlockLocked must reject it and leave state intact.
	tip := n.Tip()
	cb := CoinbaseTx(a.Address, DefaultReward, tip.Header.Height+1, "x")
	cb.TxID = cb.ComputeTxID()

	bad := Transaction{
		Version: 1,
		Vin:     []TxIn{{PrevTxID: strings.Repeat("0", 64), Vout: 0, PubKey: "04" + strings.Repeat("00", 32)}},
		Vout:    []TxOut{{Value: 1, Address: a.Address}},
	}
	bad.TxID = bad.ComputeTxID()

	b := Block{
		Header: BlockHeader{Version: 1, PrevHash: tip.Hash, Time: 1, Bits: DefaultBits, Height: tip.Header.Height + 1},
		Tx:     []Transaction{cb, bad},
	}
	b.Header.MerkleRoot = MerkleRoot(b.Tx)
	for nonce := uint64(0); ; nonce++ {
		b.Header.Nonce = nonce
		h := b.Header.Hash()
		if MeetsTarget(h, b.Header.Bits) {
			b.Hash = h
			break
		}
	}

	err = n.applyBlockLocked(b)
	if err == nil {
		t.Fatalf("applyBlockLocked should reject a block with an invalid tx")
	}
	if len(n.State.UTXO) != utxoBefore {
		t.Fatalf("UTXO set mutated after rejected block: was %d now %d", utxoBefore, len(n.State.UTXO))
	}
	if n.Height() != heightBefore {
		t.Fatalf("height changed after rejected block: was %d now %d", heightBefore, n.Height())
	}
}

// --- Coinbase must not mint more than subsidy + fees (no inflation) ---

// mineHeader solves PoW for a block in place, like the node's own mining loop.
func mineHeader(b *Block) {
	b.Header.MerkleRoot = MerkleRoot(b.Tx)
	for nonce := uint64(0); ; nonce++ {
		b.Header.Nonce = nonce
		h := b.Header.Hash()
		if MeetsTarget(h, b.Header.Bits) {
			b.Hash = h
			return
		}
	}
}

func TestCoinbaseInflationRejected(t *testing.T) {
	n := newTestNode(t)
	if _, err := n.CreateWallet("w"); err != nil {
		t.Fatal(err)
	}
	a, err := n.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}

	tip := n.Tip()
	// Empty mempool => allowed coinbase is exactly the subsidy. Pay one unit more.
	cb := CoinbaseTx(a.Address, DefaultReward+1, tip.Header.Height+1, "greedy")
	cb.TxID = cb.ComputeTxID()
	b := Block{
		Header: BlockHeader{Version: 1, PrevHash: tip.Hash, Time: time.Now().Unix(), Bits: DefaultBits, Height: tip.Header.Height + 1},
		Tx:     []Transaction{cb},
	}
	mineHeader(&b)

	heightBefore := n.Height()
	if err := n.applyBlockLocked(b); err == nil {
		t.Fatalf("block with over-valued coinbase must be rejected")
	}
	if n.Height() != heightBefore {
		t.Fatalf("rejected inflationary block must not change height")
	}

	// A coinbase paying exactly the subsidy is accepted.
	cb2 := CoinbaseTx(a.Address, DefaultReward, tip.Header.Height+1, "honest")
	cb2.TxID = cb2.ComputeTxID()
	b2 := Block{
		Header: BlockHeader{Version: 1, PrevHash: tip.Hash, Time: time.Now().Unix(), Bits: DefaultBits, Height: tip.Header.Height + 1},
		Tx:     []Transaction{cb2},
	}
	mineHeader(&b2)
	if err := n.applyBlockLocked(b2); err != nil {
		t.Fatalf("honest coinbase (subsidy only) must be accepted: %v", err)
	}
}

func TestFutureTimestampRejected(t *testing.T) {
	n := newTestNode(t)
	if _, err := n.CreateWallet("w"); err != nil {
		t.Fatal(err)
	}
	a, err := n.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	tip := n.Tip()
	cb := CoinbaseTx(a.Address, DefaultReward, tip.Header.Height+1, "future")
	cb.TxID = cb.ComputeTxID()
	b := Block{
		Header: BlockHeader{Version: 1, PrevHash: tip.Hash, Time: time.Now().Unix() + MaxFutureBlockTime + 3600, Bits: DefaultBits, Height: tip.Header.Height + 1},
		Tx:     []Transaction{cb},
	}
	mineHeader(&b)
	if err := n.applyBlockLocked(b); err == nil {
		t.Fatalf("block with far-future timestamp must be rejected")
	}
}

// --- Auth + loopback ---

func TestCookieAuthEnforcedOnRPC(t *testing.T) {
	n := newTestNode(t)
	// DisableAuth is false by default since LoadNode sets up a cookie.

	mux := http.NewServeMux()
	mux.HandleFunc("/", n.RPCHandler)

	// Request without credentials -> 401.
	req := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(`{"method":"getblockchaininfo","params":[]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /rpc should be 401, got %d", rec.Code)
	}

	// Request with correct cookie creds -> 200.
	req2 := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(`{"method":"getblockchaininfo","params":[]}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.SetBasicAuth(n.rpcUser, n.rpcPass)
	req2.RemoteAddr = "127.0.0.1:1234"
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("authenticated /rpc should be 200, got %d", rec2.Code)
	}

	// Explorer stays public.
	req3 := httptest.NewRequest(http.MethodGet, "/explorer", nil)
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("/explorer should be public 200, got %d", rec3.Code)
	}
}

func TestDumpPrivKeyLoopbackOnly(t *testing.T) {
	n := newTestNode(t)
	if _, err := n.CreateWallet("w"); err != nil {
		t.Fatal(err)
	}
	a, err := n.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	// Non-loopback must be refused even though we call the handler directly.
	if _, err := n.handleRPC("dumpprivkey", rawParams(a.Address), false); err == nil {
		t.Fatalf("dumpprivkey must be refused from non-loopback")
	}
	// Loopback must succeed.
	out, err := n.handleRPC("dumpprivkey", rawParams(a.Address), true)
	if err != nil {
		t.Fatalf("dumpprivkey from loopback failed: %v", err)
	}
	s, ok := out.(string)
	if !ok || !strings.HasPrefix(s, PrivKeyPrefix) {
		t.Fatalf("unexpected dumpprivkey output %v", out)
	}
}

func TestCookieFileWrittenAndReadable(t *testing.T) {
	dir := t.TempDir()
	n, err := LoadNode(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The cookie file must exist and be parseable back to the node's creds.
	user, pass, err := ReadCookieFile(filepath.Join(dir, CookieFile))
	if err != nil {
		t.Fatalf("ReadCookieFile: %v", err)
	}
	if user != n.rpcUser || pass != n.rpcPass {
		t.Fatalf("cookie creds do not match node creds")
	}
	if user != CookieUser {
		t.Fatalf("cookie user should be %q, got %q", CookieUser, user)
	}
}

// rawParams marshals positional args into the json.RawMessage slice that
// handleRPC expects.
func rawParams(args ...interface{}) []json.RawMessage {
	out := make([]json.RawMessage, len(args))
	for i, a := range args {
		b, _ := json.Marshal(a)
		out[i] = b
	}
	return out
}

// Guard against silly mistakes: ensure a freshly generated address verifies and
// that two different privkeys yield two different addresses.
func TestAddressUniqueness(t *testing.T) {
	n := newTestNode(t)
	if _, err := n.CreateWallet("w"); err != nil {
		t.Fatal(err)
	}
	a, err := n.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	b, err := n.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyAddress(a.Address) || !VerifyAddress(b.Address) {
		t.Fatalf("generated addresses must verify")
	}
	if a.Address == b.Address {
		t.Fatalf("two fresh addresses must differ")
	}
	// And the pubkeys must be on the curve.
	if _, err := ParsePublicKeyHex(a.PubHex); err != nil {
		t.Fatalf("pubkey A not on curve: %v", err)
	}
	if _, err := ParsePublicKeyHex(b.PubHex); err != nil {
		t.Fatalf("pubkey B not on curve: %v", err)
	}
}

// Sanity: curve order consistency (n < p, as documented in the spec).
func TestCurveOrderLessThanField(t *testing.T) {
	if CurveN.Cmp(CurveP) >= 0 {
		t.Fatalf("curve order n must be less than field prime p")
	}
	if CurveN.BitLen() < 127 {
		t.Fatalf("curve order too small for an educational 128-bit curve: %d bits", CurveN.BitLen())
	}
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	d, err := RandomScalar()
	if err != nil {
		t.Fatal(err)
	}
	h := PrivateKeyHex(d)
	got, err := ParsePrivateKeyHex(h)
	if err != nil {
		t.Fatalf("ParsePrivateKeyHex: %v", err)
	}
	if got.Cmp(d) != 0 {
		t.Fatalf("private key round-trip mismatch")
	}
	// Out-of-range must be rejected.
	if _, err := ParsePrivateKeyHex("0"); err == nil {
		t.Fatalf("zero private key must be rejected")
	}
	if _, err := ParsePrivateKeyHex(new(big.Int).Add(CurveN, big.NewInt(1)).Text(16)); err == nil {
		t.Fatalf("private key >= n must be rejected")
	}
}

// Ensure DoubleSHA256 is really double (distinct from single sha256).
func TestDoubleSHA256(t *testing.T) {
	data := []byte("toycoin")
	single := sha256sum(data)
	double := DoubleSHA256(data)
	if bytes.Equal(single, double) {
		t.Fatalf("DoubleSHA256 must differ from a single sha256")
	}
	// And double == sha256(sha256(x)).
	if !bytes.Equal(double, sha256sum(single)) {
		t.Fatalf("DoubleSHA256 incorrect")
	}
}

func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// --- paramInt: reject non-integer floats ---

func TestParamIntRejectsFraction(t *testing.T) {
	// 2.5 must NOT be silently truncated to 2.
	v, err := paramInt([]json.RawMessage{json.RawMessage("2.5")}, 0)
	if err == nil {
		t.Fatalf("paramInt must reject 2.5, got %d", v)
	}
}

func TestParamIntAcceptsInteger(t *testing.T) {
	v, err := paramInt([]json.RawMessage{json.RawMessage("3")}, 0)
	if err != nil {
		t.Fatalf("paramInt(3): %v", err)
	}
	if v != 3 {
		t.Fatalf("paramInt(3) = %d, want 3", v)
	}
}

func TestParamIntAcceptsWholeNumberFloat(t *testing.T) {
	// 2.0 is a whole number expressed as float; accept it as 2.
	v, err := paramInt([]json.RawMessage{json.RawMessage("2.0")}, 0)
	if err != nil {
		t.Fatalf("paramInt(2.0): %v", err)
	}
	if v != 2 {
		t.Fatalf("paramInt(2.0) = %d, want 2", v)
	}
}

func TestParamIntMissing(t *testing.T) {
	if _, err := paramInt(nil, 0); err == nil {
		t.Fatalf("paramInt must error on missing parameter")
	}
}

// --- RPC: POST-only and body size cap ---

func TestRPCRejectsGET(t *testing.T) {
	n := newTestNode(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", n.RPCHandler)

	req := httptest.NewRequest(http.MethodGet, "/rpc", nil)
	req.SetBasicAuth(n.rpcUser, n.rpcPass)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /rpc should be 405, got %d", rec.Code)
	}
}

func TestRPCRejectsOversizedBody(t *testing.T) {
	n := newTestNode(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", n.RPCHandler)

	// Build a body larger than MaxRPCBodyBytes.
	huge := make([]byte, MaxRPCBodyBytes+1024)
	for i := range huge {
		huge[i] = 'a'
	}
	body := append([]byte(`{"method":"getblockchaininfo","params":["`), huge...)
	body = append(body, []byte(`"]}`)...)

	req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewReader(body))
	req.SetBasicAuth(n.rpcUser, n.rpcPass)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// The MaxBytesReader triggers an error during decode; the handler returns it
	// via writeRPC as a JSON error. We just assert the request did NOT succeed
	// (i.e. it is not a clean getblockchaininfo result).
	var resp struct {
		Error  string          `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("could not parse response: %v body=%q", err, rec.Body.String())
	}
	if resp.Error == "" {
		t.Fatalf("oversized body should produce an error, got result=%s", resp.Result)
	}
}

// --- MineBlocks: stale block after a concurrent tip advance is skipped, not fatal ---

// TestMineBlocksSkipsStaleBlock simulates the race: while MineBlocks is mining a
// block, another caller advances the tip. The mined block becomes stale and
// must be skipped (continue) rather than aborting mining with an error.
//
// We cannot easily interleave a tip advance inside MineBlocks' PoW loop from a
// test, so we verify the invariant the skip logic relies on: a block whose
// PrevHash no longer matches the current tip is rejected by applyBlockLocked.
// MineBlocks' `if n.Tip().Hash != b.Header.PrevHash { continue }` guard uses the
// same comparison before ever calling applyBlockLocked.
func TestMineBlocksSkipsStaleBlock(t *testing.T) {
	n := newTestNode(t)
	if _, err := n.CreateWallet("w"); err != nil {
		t.Fatal(err)
	}
	a, err := n.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}

	// Mine two blocks: height goes 0 -> 1 -> 2.
	if _, err := n.MineBlocks(2, a.Address); err != nil {
		t.Fatal(err)
	}
	if n.Height() != 2 {
		t.Fatalf("expected height 2 after mining, got %d", n.Height())
	}
	heightBefore := n.Height()
	stalePrevHash := n.State.Blocks[1].Hash // the block at height 1, NOT the tip

	// Build a block that claims to follow height 1 (stalePrevHash) but with the
	// height of the current tip + 1. This mimics a block mined on an old tip.
	tip := n.Tip()
	stale := Block{
		Header: BlockHeader{
			Version: 1, PrevHash: stalePrevHash,
			Time: time.Now().Unix(), Bits: DefaultBits, Height: tip.Header.Height + 1,
		},
		Tx: []Transaction{CoinbaseTx(a.Address, DefaultReward, tip.Header.Height+1, "stale")},
	}
	stale.Tx[0].TxID = stale.Tx[0].ComputeTxID()
	mineHeader(&stale)

	if err := n.applyBlockLocked(stale); err == nil {
		t.Fatalf("a stale-prev-hash block must be rejected by applyBlockLocked")
	}
	// The rejected block must not have changed the height.
	if n.Height() != heightBefore {
		t.Fatalf("stale block unexpectedly changed height: got %d want %d", n.Height(), heightBefore)
	}
}


