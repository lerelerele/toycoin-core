# Roadmap

## v0.1.3 (current)

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

## v0.2 next

- Proper block locator sync.
- Fork choice / reorg handling (currently nodes that diverge at the same height
  stay split until reset).
- Peer banning / invalid block handling.
- Faucet service.
- Raw transaction hex format.
- Challenge UTXO module.
- Kangaroo estimator and toy challenge commands.

## v0.3 next

- Real P2P message protocol.
- Better scripts: P2PKH, P2PK, multisig-toy.
- Dedicated explorer service.
- Docker compose seed/student files.
- Course notebooks.
