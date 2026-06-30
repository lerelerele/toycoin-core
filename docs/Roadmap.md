# Roadmap

## v0.1.2 included

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

## v0.2 next

- Proper block locator sync.
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


## v0.1.2

- Replaced the provisional `toy1` + Base58 address construction with real Bech32 witness-v0 `tn1q...` addresses and checksum validation.
