# Roadmap

## v0.2.0 (current)

- **Fork choice / reorg**: the node keeps a full block index (including side
  branches) and always follows the most-work chain. When a peer's branch becomes
  heavier it reorgs onto it, rebuilding the UTXO set and returning disconnected
  txs to the mempool. Sync walks a peer's chain back to the common ancestor, so
  two diverged nodes now converge instead of staying split. `getblockchaininfo`
  exposes `chainwork` and `known_blocks`.
- **Authority checkpoints**: an operator holding an offline authority key can
  sign `{height, blockhash}` checkpoints; nodes started with `-authoritypubkey`
  refuse to follow any chain that does not contain the checkpointed block, even a
  heavier one. This lets a teacher pin the canonical chain when nodes are exposed
  beyond a trusted LAN. See [Authority-Checkpoints.md](Authority-Checkpoints.md).
- **Checkpoint propagation**: checkpoints spread across the network both ways —
  pushed to peers when first accepted and pulled during sync — so submitting a
  checkpoint to the seed is enough for the whole class to enforce it.
- **Inventory-relay gossip**: blocks and txs propagate transitively — any node
  that accepts a new item announces it to peers via `inv`, and peers pull only
  what they lack with `getdata` (`getblock`/`gettx`). Nodes with a reachable
  `-externaladdr` announce inventory; nodes without one fall back to pushing full
  data. Peers are learned from `inv` (address gossip), so the mesh becomes
  bidirectional. See [Networking-Gossip.md](Networking-Gossip.md).
- **Public read-only peer sync**: read-only chain queries and fully-validated
  consensus pushes (submitblock/submittransaction/submitcheckpoint/inv) no longer
  require the cookie, so nodes actually sync in the default authenticated mode.
  Wallet and key operations stay behind cookie auth; dumpprivkey stays loopback.

## v0.1.3

- Consensus: the coinbase can no longer pay more than `subsidy + fees`; blocks
  with an over-valued coinbase are rejected (no unbounded inflation).
- Consensus: blocks timestamped more than `MaxFutureBlockTime` (2h) ahead of the
  node clock are rejected.
- Single `core.Version` constant; daemon log, CLI usage and `getnetworkinfo` all
  report the same version.
- Removed dead Base58 helpers left over from the pre-Bech32 address format.

## v0.1.2

- Windows and WSL/Linux builds.
- `toycoind` JSON-RPC server.
- `toycoin-cli` command client.
- `toy128k1f` curve.
- Wallets and addresses.
- UTXO chain.
- SHA256d proof of work.
- Mempool.
- Basic shared-chain sync through RPC peers.
- Basic HTML explorer.
- Replaced the provisional `toy1` + Base58 address construction with real Bech32
  witness-v0 `tn1q...` addresses and checksum validation.

## v0.3 next

- Proper block locator sync (current sync walks back block-by-block).
- Peer banning / invalid block handling.
- Rate-limiting / inv de-dup cache (today loop-safety relies on "already have";
  a short seen-inv cache would cut redundant getdata under churn).
- Raw TCP P2P transport with a `version`/`verack` handshake and persistent
  connections. The gossip protocol (inv/getdata, block/tx/checkpoint relay,
  address learning) already exists as of v0.2.0, but it currently rides on the
  HTTP-RPC transport; this would move it onto a real socket protocol.
- Faucet service.
- Raw transaction hex format.
- Challenge UTXO module.
- Kangaroo estimator and toy challenge commands.
- Better scripts: P2PKH, P2PK, multisig-toy.
- Dedicated explorer service.
- Docker compose seed/student files.
- Course notebooks.
