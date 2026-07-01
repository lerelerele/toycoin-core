package core

import (
	"encoding/json"
	"log"
)

// Inventory item types for gossip announcements.
const (
	InvBlock = "block"
	InvTx    = "tx"
)

// InvItem announces that a node has a block or transaction with the given hash,
// without shipping the full object. Peers that lack it pull it with getdata
// (getblock / gettx). This is the Bitcoin-style inv/getdata inventory relay.
type InvItem struct {
	Type string `json:"type"` // InvBlock | InvTx
	Hash string `json:"hash"`
}

// relayInv propagates newly-accepted items to peers for transitive gossip.
//
//   - If this node advertises a reachable address (SelfURL set), it announces an
//     inv and lets each peer pull only what it is missing — efficient.
//   - If it has no advertised address (e.g. a student node with no inbound
//     reachability), it cannot be pulled from, so it falls back to pushing the
//     full block/tx. This still floods correctly along the peer edges.
//
// Loops terminate because a peer that already has an item does not re-relay it
// (see SubmitBlock/SubmitTx). `exclude` skips one peer (usually the sender) to
// cut obvious back-chatter; correctness does not depend on it.
func (n *Node) relayInv(items []InvItem, exclude string) {
	if len(items) == 0 {
		return
	}
	n.mu.Lock()
	self := n.SelfURL
	peers := append([]string{}, n.Peers...)
	n.mu.Unlock()

	for _, p := range peers {
		if p == exclude || p == self {
			continue
		}
		if self != "" {
			_, _ = rpcPost(p, "inv", []interface{}{self, items})
			continue
		}
		// Fallback: push full data since peers cannot pull back from us.
		for _, it := range items {
			switch it.Type {
			case InvBlock:
				if b, ok := n.blockByHash(it.Hash); ok {
					_, _ = rpcPost(p, "submitblock", []interface{}{b})
				}
			case InvTx:
				if tx, ok := n.txByHash(it.Hash); ok {
					_, _ = rpcPost(p, "submittransaction", []interface{}{tx})
				}
			}
		}
	}
}

// HandleInv reacts to an inv announcement from `from`: it learns the sender as a
// peer (address gossip), then pulls any items it is missing and submits them.
// SubmitBlock/SubmitTx relay genuinely-new items onward, giving transitive
// gossip across the network.
func (n *Node) HandleInv(from string, items []InvItem) {
	from = normalizePeerURL(from)
	if from != "" {
		n.mu.Lock()
		added := n.addPeerLocked(from)
		if added {
			_ = n.Save()
		}
		n.mu.Unlock()
	}
	for _, it := range items {
		n.mu.Lock()
		have := n.alreadyHaveLocked(it)
		n.mu.Unlock()
		if have {
			continue
		}
		if from == "" {
			continue // announced without a reachable address; nothing to pull from
		}
		switch it.Type {
		case InvBlock:
			b, err := rpcCallBlock(from, "getblock", []interface{}{it.Hash})
			if err != nil {
				continue
			}
			if err := n.SubmitBlock(b); err != nil {
				log.Printf("[NET] inv: block %s from %s rejected: %v", it.Hash, from, err)
			}
		case InvTx:
			tx, err := rpcGetTx(from, it.Hash)
			if err != nil {
				continue
			}
			if err := n.SubmitTx(tx); err != nil {
				log.Printf("[NET] inv: tx %s from %s rejected: %v", it.Hash, from, err)
			}
		}
	}
}

// addPeerLocked adds a peer URL if new and under the cap. Caller holds n.mu.
// Returns true if the peer set changed. It never adds this node's own address.
func (n *Node) addPeerLocked(url string) bool {
	url = normalizePeerURL(url)
	if url == "" || url == n.SelfURL {
		return false
	}
	for _, p := range n.Peers {
		if p == url {
			return false
		}
	}
	if len(n.Peers) >= MaxPeers {
		return false
	}
	n.Peers = append(n.Peers, url)
	n.State.Peers = n.Peers
	log.Printf("[NET] learned peer %s (now %d peers)", url, len(n.Peers))
	return true
}

// alreadyHaveLocked reports whether we already hold an inventory item. Caller
// holds n.mu.
func (n *Node) alreadyHaveLocked(it InvItem) bool {
	switch it.Type {
	case InvBlock:
		return n.hasBlockLocked(it.Hash)
	case InvTx:
		for _, tx := range n.State.Mempool {
			if tx.TxID == it.Hash {
				return true
			}
		}
		return false
	default:
		return true // unknown type: pretend we have it so we never chase it
	}
}

// blockByHash returns a known block (from any branch) by hash.
func (n *Node) blockByHash(hash string) (Block, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	b, ok := n.State.Index[hash]
	return b, ok
}

// txByHash returns a mempool transaction by id.
func (n *Node) txByHash(txid string) (Transaction, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, tx := range n.State.Mempool {
		if tx.TxID == txid {
			return tx, true
		}
	}
	return Transaction{}, false
}

// rpcGetTx pulls a mempool transaction from a peer by id.
func rpcGetTx(peer, txid string) (Transaction, error) {
	raw, err := rpcPost(peer, "gettx", []interface{}{txid})
	if err != nil {
		return Transaction{}, err
	}
	var tx Transaction
	return tx, json.Unmarshal(raw, &tx)
}
