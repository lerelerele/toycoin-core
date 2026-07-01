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

	err = n.acceptBlockLocked(b)
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
	if err := n.acceptBlockLocked(b); err == nil {
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
	if err := n.acceptBlockLocked(b2); err != nil {
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
	if err := n.acceptBlockLocked(b); err == nil {
		t.Fatalf("block with far-future timestamp must be rejected")
	}
}

// --- Auth + loopback ---

func TestCookieAuthEnforcedOnRPC(t *testing.T) {
	n := newTestNode(t)
	// DisableAuth is false by default since LoadNode sets up a cookie.

	mux := http.NewServeMux()
	mux.HandleFunc("/", n.RPCHandler)

	// A wallet method without credentials -> 401 (still protected).
	req := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(`{"method":"getbalance","params":[]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated wallet /rpc should be 401, got %d", rec.Code)
	}

	// Same wallet method with correct cookie creds -> 200.
	req2 := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(`{"method":"getbalance","params":[]}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.SetBasicAuth(n.rpcUser, n.rpcPass)
	req2.RemoteAddr = "127.0.0.1:1234"
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("authenticated wallet /rpc should be 200, got %d", rec2.Code)
	}

	// A public read-only method (used by peer sync) must work WITHOUT the cookie.
	req3 := httptest.NewRequest(http.MethodPost, "/rpc", strings.NewReader(`{"method":"getblockchaininfo","params":[]}`))
	req3.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("public getblockchaininfo should be 200 without auth, got %d", rec3.Code)
	}

	// Explorer stays public.
	req4 := httptest.NewRequest(http.MethodGet, "/explorer", nil)
	rec4 := httptest.NewRecorder()
	mux.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusOK {
		t.Fatalf("/explorer should be public 200, got %d", rec4.Code)
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

// --- Fork choice: a competing same-height branch is stored but does not reorg ---

// TestCompetingBlockDoesNotReorgOnTie builds a valid block that forks off the
// block at height 1 (a sibling of our current tip). It has the same height and
// therefore the same cumulative work as the active chain, so acceptBlockLocked
// must keep it as a side branch without switching the active tip (ties favour
// the incumbent chain). It must not error: a fork is a normal event, not a
// rejection. This also covers the invariant MineBlocks' stale-tip skip relies
// on — a block that does not extend the current tip never advances it.
func TestCompetingBlockDoesNotReorgOnTie(t *testing.T) {
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
	tipBefore := n.Tip().Hash
	parent := n.State.Blocks[1] // block at height 1: fork point for the sibling

	// A valid competing block at height 2 built on block 1 (sibling of the tip).
	fork := Block{
		Header: BlockHeader{
			Version: 1, PrevHash: parent.Hash,
			Time: time.Now().Unix(), Bits: DefaultBits, Height: parent.Header.Height + 1,
		},
		Tx: []Transaction{CoinbaseTx(a.Address, DefaultReward, parent.Header.Height+1, "sibling")},
	}
	fork.Tx[0].TxID = fork.Tx[0].ComputeTxID()
	mineHeader(&fork)

	if err := n.acceptBlockLocked(fork); err != nil {
		t.Fatalf("a valid competing block must be accepted (stored), not errored: %v", err)
	}
	// Tie => no reorg: tip and height unchanged.
	if n.Height() != 2 || n.Tip().Hash != tipBefore {
		t.Fatalf("competing same-height block must not reorg: height=%d tip=%s", n.Height(), n.Tip().Hash)
	}
	// But the sibling must be retained in the index for future fork choice.
	if !n.hasBlockLocked(fork.Hash) {
		t.Fatalf("competing block should be stored in the index")
	}
}

// TestReorgToHeavierChain extends the sibling branch by one more block so that
// branch becomes strictly heavier than the active chain, and verifies the node
// reorgs onto it: the active tip switches and the UTXO set is rebuilt.
func TestReorgToHeavierChain(t *testing.T) {
	n := newTestNode(t)
	if _, err := n.CreateWallet("w"); err != nil {
		t.Fatal(err)
	}
	a, err := n.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.MineBlocks(2, a.Address); err != nil { // heights 1,2 on chain A
		t.Fatal(err)
	}
	parent := n.State.Blocks[1] // height 1

	// Build branch B: two blocks (heights 2 and 3) on top of block 1, so B has
	// more cumulative work than chain A (which tops out at height 2).
	mkBlock := func(prev Block, tag string) Block {
		b := Block{
			Header: BlockHeader{Version: 1, PrevHash: prev.Hash, Time: time.Now().Unix(), Bits: DefaultBits, Height: prev.Header.Height + 1},
			Tx:     []Transaction{CoinbaseTx(a.Address, DefaultReward, prev.Header.Height+1, tag)},
		}
		b.Tx[0].TxID = b.Tx[0].ComputeTxID()
		mineHeader(&b)
		return b
	}
	b2 := mkBlock(parent, "B-h2")
	b3 := mkBlock(b2, "B-h3")

	// Deliver B out of the active chain. B-h2 only ties chain A (both height 2),
	// so it must NOT reorg yet.
	if err := n.acceptBlockLocked(b2); err != nil {
		t.Fatalf("accept B-h2: %v", err)
	}
	if n.Height() != 2 {
		t.Fatalf("B-h2 ties chain A and must not reorg; height=%d", n.Height())
	}
	// B-h3 makes branch B strictly heavier, triggering the reorg.
	if err := n.acceptBlockLocked(b3); err != nil {
		t.Fatalf("accept B-h3: %v", err)
	}
	if n.Height() != 3 {
		t.Fatalf("after reorg height should be 3, got %d", n.Height())
	}
	if n.Tip().Hash != b3.Hash {
		t.Fatalf("active tip should be B-h3 after reorg, got %s", n.Tip().Hash)
	}
	// The UTXO set must reflect branch B: exactly the coinbases of genesis-excluded
	// blocks 1, B-h2, B-h3 (3 mature/immature coinbase outputs), none from chain A.
	if len(n.State.UTXO) != 3 {
		t.Fatalf("expected 3 UTXOs after reorg to B, got %d", len(n.State.UTXO))
	}
}

// TestSyncReorgsAcrossNodes is the end-to-end proof of fork choice over the
// wire: two nodes mine divergent chains, then the node on the shorter fork
// syncs from a peer on the heavier chain and reorgs onto it. This is exactly
// the "two students diverged" scenario that used to leave nodes stuck.
func TestSyncReorgsAcrossNodes(t *testing.T) {
	mk := func() *Node {
		dir := t.TempDir()
		n, err := LoadNode(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		n.DisableAuth = true // peer RPC in this test is unauthenticated
		if _, err := n.CreateWallet("w"); err != nil {
			t.Fatal(err)
		}
		return n
	}
	n1, n2 := mk(), mk()
	a1, err := n1.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	a2, err := n2.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}

	// n2 builds the heavier chain (height 3); n1 sits on a shorter fork (height 1).
	if _, err := n2.MineBlocks(3, a2.Address); err != nil {
		t.Fatal(err)
	}
	if _, err := n1.MineBlocks(1, a1.Address); err != nil {
		t.Fatal(err)
	}
	if n1.Tip().Hash == n2.Tip().Hash {
		t.Fatal("precondition: the two nodes should be on different chains")
	}

	srv2 := httptest.NewServer(http.HandlerFunc(n2.RPCHandler))
	defer srv2.Close()
	n1.Peers = []string{srv2.URL}

	n1.SyncOnce()

	if n1.Height() != 3 {
		t.Fatalf("n1 should reorg to the peer's height 3, got %d", n1.Height())
	}
	if n1.Tip().Hash != n2.Tip().Hash {
		t.Fatalf("n1 tip %s should match n2 tip %s after sync", n1.Tip().Hash, n2.Tip().Hash)
	}
}

// --- Authority checkpoints ---

// coinbaseBlockOn builds and mines a valid coinbase-only child of parent.
func coinbaseBlockOn(parent Block, addr, tag string) Block {
	b := Block{
		Header: BlockHeader{Version: 1, PrevHash: parent.Hash, Time: time.Now().Unix(), Bits: DefaultBits, Height: parent.Header.Height + 1},
		Tx:     []Transaction{CoinbaseTx(addr, DefaultReward, parent.Header.Height+1, tag)},
	}
	b.Tx[0].TxID = b.Tx[0].ComputeTxID()
	mineHeader(&b)
	return b
}

// newAuthorityKey returns a fresh authority (priv, pubhex) pair for tests.
func newAuthorityKey(t *testing.T) (*big.Int, string) {
	t.Helper()
	d, err := RandomScalar()
	if err != nil {
		t.Fatal(err)
	}
	P, err := PrivateToPublic(d)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyHex(P)
	if err != nil {
		t.Fatal(err)
	}
	return d, pub
}

func TestCheckpointSignVerify(t *testing.T) {
	d, pub := newAuthorityKey(t)
	cp, err := SignCheckpoint(d, 5, "ABCDEF0123")
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	if err := VerifyCheckpoint(cp, pub); err != nil {
		t.Fatalf("valid checkpoint should verify against its authority: %v", err)
	}
	if err := VerifyCheckpoint(cp, ""); err != nil {
		t.Fatalf("checkpoint should verify with no authority pinned: %v", err)
	}
	// Wrong authority key pinned.
	_, otherPub := newAuthorityKey(t)
	if err := VerifyCheckpoint(cp, otherPub); err == nil {
		t.Fatalf("checkpoint must not verify against a different authority key")
	}
	// Tampered block hash.
	bad := cp
	bad.BlockHash = "deadbeef"
	if err := VerifyCheckpoint(bad, pub); err == nil {
		t.Fatalf("tampered checkpoint must fail verification")
	}
}

func TestSubmitCheckpointRequiresAuthority(t *testing.T) {
	n := newTestNode(t) // no AuthorityPubKey configured
	d, _ := newAuthorityKey(t)
	cp, _ := SignCheckpoint(d, 0, n.Tip().Hash)
	if err := n.SubmitCheckpoint(cp); err == nil {
		t.Fatalf("a node without an authority key must reject checkpoints")
	}
}

// A checkpoint must veto a strictly heavier fork that does not contain the
// checkpointed block.
func TestCheckpointVetoesHeavierFork(t *testing.T) {
	n := newTestNode(t)
	d, pub := newAuthorityKey(t)
	n.AuthorityPubKey = pub
	if _, err := n.CreateWallet("w"); err != nil {
		t.Fatal(err)
	}
	a, err := n.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.MineBlocks(2, a.Address); err != nil { // chain A: heights 1,2
		t.Fatal(err)
	}
	a2 := n.Tip()
	// Bless chain A at height 2.
	cp, err := SignCheckpoint(d, 2, a2.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.SubmitCheckpoint(cp); err != nil {
		t.Fatalf("SubmitCheckpoint: %v", err)
	}

	// Build a heavier fork B off height 1 (so it excludes the checkpointed A@2).
	parent := n.State.Blocks[1] // height 1
	b2 := coinbaseBlockOn(parent, a.Address, "B-h2")
	b3 := coinbaseBlockOn(b2, a.Address, "B-h3")
	if err := n.acceptBlockLocked(b2); err != nil {
		t.Fatal(err)
	}
	if err := n.acceptBlockLocked(b3); err != nil {
		t.Fatal(err)
	}
	// Despite branch B being heavier (height 3 > 2), the checkpoint vetoes it.
	if n.Tip().Hash != a2.Hash || n.Height() != 2 {
		t.Fatalf("checkpoint should pin chain A; got tip=%s height=%d", n.Tip().Hash, n.Height())
	}
}

// A checkpoint pointing at a sibling branch must force the node off its current
// (now forbidden) chain and onto the blessed branch, even on equal work.
func TestCheckpointForcesSwitchToBlessedBranch(t *testing.T) {
	n := newTestNode(t)
	d, pub := newAuthorityKey(t)
	n.AuthorityPubKey = pub
	if _, err := n.CreateWallet("w"); err != nil {
		t.Fatal(err)
	}
	a, err := n.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.MineBlocks(2, a.Address); err != nil { // chain A: heights 1,2
		t.Fatal(err)
	}
	// Sibling B at height 2 off height 1 (a tie: node stays on A for now).
	parent := n.State.Blocks[1]
	b2 := coinbaseBlockOn(parent, a.Address, "B-h2")
	if err := n.acceptBlockLocked(b2); err != nil {
		t.Fatal(err)
	}
	if n.Height() != 2 || n.Tip().Header.Height != 2 {
		t.Fatalf("tie must not reorg; height=%d", n.Height())
	}
	// Now the authority blesses branch B at height 2.
	cp, err := SignCheckpoint(d, 2, b2.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.SubmitCheckpoint(cp); err != nil {
		t.Fatalf("SubmitCheckpoint: %v", err)
	}
	if n.Tip().Hash != b2.Hash {
		t.Fatalf("node should switch to the blessed branch B; got tip=%s", n.Tip().Hash)
	}
}

// TestCheckpointPropagatesOnSync proves a node learns the authority checkpoint
// from a peer during sync (the mechanism a student node relies on to receive the
// teacher's checkpoint from the seed), and then enforces it.
func TestCheckpointPropagatesOnSync(t *testing.T) {
	d, pub := newAuthorityKey(t)
	mk := func() *Node {
		dir := t.TempDir()
		n, err := LoadNode(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		n.DisableAuth = true
		n.AuthorityPubKey = pub
		if _, err := n.CreateWallet("w"); err != nil {
			t.Fatal(err)
		}
		return n
	}
	seed, student := mk(), mk()
	addr, err := seed.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.MineBlocks(2, addr.Address); err != nil {
		t.Fatal(err)
	}
	// The authority blesses the seed's height-2 tip.
	cp, err := SignCheckpoint(d, 2, seed.Tip().Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.SubmitCheckpoint(cp); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(seed.RPCHandler))
	defer srv.Close()
	student.Peers = []string{srv.URL}

	student.SyncOnce() // pulls blocks AND the checkpoint

	if student.State.Checkpoint == nil || student.State.Checkpoint.BlockHash != seed.Tip().Hash {
		t.Fatalf("student should have learned the seed's checkpoint via sync")
	}
	if student.Tip().Hash != seed.Tip().Hash {
		t.Fatalf("student should be on the blessed chain; got tip=%s", student.Tip().Hash)
	}
}

// --- Gossip / inventory relay ---

// waitFor polls cond until true or the deadline, failing the test on timeout.
// Gossip is asynchronous (inv triggers background getdata), so tests wait for
// propagation rather than assuming it is instantaneous.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

func heightOf(n *Node) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.Height()
}

func mempoolLen(n *Node) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.State.Mempool)
}

// gossipNode spins up a node with its own httptest server and (optionally) an
// advertised SelfURL so peers can pull from it.
func gossipNode(t *testing.T, advertise bool) (*Node, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	n, err := LoadNode(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	n.DisableAuth = true
	if _, err := n.CreateWallet("w"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(n.RPCHandler))
	t.Cleanup(srv.Close)
	if advertise {
		n.SelfURL = srv.URL
	}
	return n, srv
}

// TestGossipRelaysBlockTransitively: A mines, B is A's only peer, C is B's only
// peer. The block must reach C via B re-relaying it — A and C are not direct
// peers. Uses the full-push fallback (no SelfURL advertised).
func TestGossipRelaysBlockTransitively(t *testing.T) {
	a, _ := gossipNode(t, false)
	b, bsrv := gossipNode(t, false)
	c, csrv := gossipNode(t, false)
	a.Peers = []string{bsrv.URL}
	b.Peers = []string{csrv.URL}

	addr, err := a.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.MineBlocks(1, addr.Address); err != nil { // triggers relay to B, then B->C
		t.Fatal(err)
	}
	waitFor(t, func() bool { return heightOf(b) == 1 }, "B to receive the block from A")
	waitFor(t, func() bool { return heightOf(c) == 1 }, "C to receive the block relayed via B")
	if c.Tip().Hash != a.Tip().Hash {
		t.Fatalf("C tip should equal A tip after transitive gossip")
	}
}

// TestGossipInvGetdataBlock: A advertises a reachable URL, so it announces an
// inv and B pulls the block via getdata (getblock) rather than being pushed the
// full block. Verifies the inv/getdata path end to end.
func TestGossipInvGetdataBlock(t *testing.T) {
	a, _ := gossipNode(t, true) // advertises SelfURL -> uses inv
	b, bsrv := gossipNode(t, false)
	a.Peers = []string{bsrv.URL}

	addr, err := a.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.MineBlocks(1, addr.Address); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return heightOf(b) == 1 }, "B to pull the inv-announced block from A")
	// B should also have learned A as a peer from the inv's `from` field.
	waitFor(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		for _, p := range b.Peers {
			if p == a.SelfURL {
				return true
			}
		}
		return false
	}, "B to learn A as a peer via inv address gossip")
}

// TestGossipRelaysTxTransitively: A, B, C in a line share a chain, then A
// broadcasts a spend; the tx must reach C's mempool via B.
func TestGossipRelaysTxTransitively(t *testing.T) {
	a, asrv := gossipNode(t, false)
	b, bsrv := gossipNode(t, false)
	c, csrv := gossipNode(t, false)
	// Wire a mesh so blocks and txs can flow A<->B<->C.
	a.Peers = []string{bsrv.URL}
	b.Peers = []string{asrv.URL, csrv.URL}
	c.Peers = []string{bsrv.URL}

	addr, err := a.GetNewAddress()
	if err != nil {
		t.Fatal(err)
	}
	// Mine enough for a mature, spendable coinbase; blocks gossip to B and C.
	if _, err := a.MineBlocks(3, addr.Address); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return heightOf(b) == 3 && heightOf(c) == 3 }, "B and C to sync A's blocks")

	dest, err := b.GetNewAddress() // pay someone; B's address is fine
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateSendTx(dest.Address, 5*Coin); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return mempoolLen(b) == 1 }, "B to receive the tx from A")
	waitFor(t, func() bool { return mempoolLen(c) == 1 }, "C to receive the tx relayed via B")
}


