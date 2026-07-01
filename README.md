# Toycoin Core — Toynet128 v0.1.3

Toycoin Core is an educational Bitcoin-like blockchain for classrooms.

It is intentionally **not compatible with Bitcoin** and must never be used for real funds.

## What is included

- `toycoind`: Toynet128 node with JSON-RPC and simple explorer.
- `toycoin-cli`: Bitcoin-Core-like CLI.
- `toy128k1f`: reproducible educational elliptic curve.
- UTXO model.
- Native Toycoin addresses: real Bech32 witness-v0 format `tn1q...` with checksum.
- Wallet creation and fresh change addresses.
- PoW mining with SHA256d; miners collect fees (coinbase = subsidy + fees).
- Basic shared-chain sync through seed RPC peers.
- Cookie-file RPC authentication (like Bitcoin Core); `dumpprivkey` restricted to loopback.
- Security report for exposed public keys.

## Build

### WSL / Linux

```bash
./build/build-linux.sh
```

### Windows PowerShell

```powershell
.\build\build-windows.ps1
```

Or cross-compile from WSL:

```bash
GOOS=windows GOARCH=amd64 go build -o dist/windows-amd64/toycoind.exe ./cmd/toycoind
GOOS=windows GOARCH=amd64 go build -o dist/windows-amd64/toycoin-cli.exe ./cmd/toycoin-cli
```

## Quick start, local node

Terminal 1:

```bash
./dist/linux-amd64/toycoind -toynet128
```

Terminal 2:

```bash
./dist/linux-amd64/toycoin-cli createwallet alumno
ADDR=$(./dist/linux-amd64/toycoin-cli getnewaddress | tr -d '"')
./dist/linux-amd64/toycoin-cli generatetoaddress 3 "$ADDR"
./dist/linux-amd64/toycoin-cli getbalance
./dist/linux-amd64/toycoin-cli getblockchaininfo
```

Explorer:

```text
http://127.0.0.1:28443/explorer
```

## Seed node for a shared Toynet128

On a public server:

```bash
toycoind -toynet128 -rpclisten=0.0.0.0 -rpcport=28443
```

Student node:

```bash
toycoind -toynet128 -addnode=http://seed1.example.org:28443
```

This v0.1.3 gossips blocks and txs with a Bitcoin-style inventory relay
(`inv`/`getdata`) over the JSON-RPC transport — new items propagate transitively
and peers pull only what they lack (see [docs/Networking-Gossip.md](docs/Networking-Gossip.md)).
It is not a raw TCP P2P protocol yet. Nodes follow the most-work chain and reorg
automatically, so diverged nodes converge. On a trusted LAN that is enough; when exposing nodes further, an
operator can pin the canonical chain with **authority checkpoints** (see
[docs/Authority-Checkpoints.md](docs/Authority-Checkpoints.md)):

```bash
toycoin-cli genauthoritykey                 # once, offline
toycoind -toynet128 -authoritypubkey <pub>  # on every node
```

## RPC security

The `/rpc` endpoint is protected by **cookie-file authentication** (like Bitcoin
Core). On every startup `toycoind` generates a random token and writes it to
`<datadir>/.cookie` as `__cookie__:<token>` (mode 0600). `toycoin-cli` reads
that file automatically and sends HTTP Basic Auth, so the CLI "just works"
against a local node.

- Wallet and node-config RPC methods on `/rpc` require valid cookie credentials.
- Read-only chain queries and fully-validated consensus pushes on `/rpc`
  (`getblockchaininfo`, `getblock`, `submitblock`, `submittransaction`,
  `submitcheckpoint`, …) are **public**, so peers can sync without sharing a
  cookie. They expose the same data as `/explorer`, and pushed blocks/txs are
  validated (and checkpoints signature-checked) before they can change state.
- `/` and `/explorer` stay public (read-only chain state).
- `dumpprivkey` is restricted to **loopback** connections (`127.0.0.1` / `::1`)
  even with valid credentials, so a remote peer that somehow obtained the
  cookie cannot export private keys.

The cookie is regenerated on each restart, so a leaked old cookie becomes
useless. Point the CLI at a non-default data dir with `-datadir=<path>` so it
can find the cookie.

> **Warning — no TLS.** The cookie protects against casual access and
> share-the-network misuse, but it does **not** protect against an active
> attacker on the wire (MITM) if you expose `toycoind` on the public internet
> over plain HTTP. For a classroom on a trusted LAN this is the intended threat
> model; do not expose a node with funds to the open internet without TLS or an
> SSH tunnel.

## Basic commands

```bash
toycoin-cli getblockchaininfo
toycoin-cli curveinfo
toycoin-cli createwallet alice
toycoin-cli getnewaddress
toycoin-cli generatetoaddress 1 tn1q...
toycoin-cli getbalance
toycoin-cli listunspent
toycoin-cli sendtoaddress tn1q... 10
toycoin-cli getrawmempool
toycoin-cli security walletreport
```


## Address format

Toycoin no longer uses the weak-looking `toy1` + Base58 construction.

New addresses use a Bech32-style native format:

```text
HRP: tn
separator: 1
witness version: 0 (encoded as q)
program: ToyHash160(pubkey) = SHA256(pubkey)[:20]
checksum: 6 Bech32 characters
example: tn1q8z4h8k7k0q7vwrnvh0aqt7j7q0xp6mcmv7vx9w
```

Old v0.1 addresses such as `toy1b28...` are intentionally obsolete. For a clean classroom chain after upgrading, reset the Toycoin data directory or start a new Toynet128 genesis/state.

## Educational wallet rule

Toycoin wallet uses a **sweep + fresh change** model:

- spend all available wallet UTXOs;
- send payment to destination;
- send change to a new own address;
- leave revealed public keys empty.

This makes it easy to teach why Bitcoin wallets should not reuse exposed keys.

## toy128k1f

```text
Curve: y² = x³ + 7 mod p
p = 0xcc3e373aa65e4fc92bfba193af40d4e7
a = 0
b = 7
Gx = 0xc10a8eb0ef340645a767114393fc4786
Gy = 0xa50d20b0925585547a2a396090e48f7a
n = 0xcc3e373aa65e4fc91c93ff817b7e1259
h = 1
Seed = "Toy128k1f for Toycoin Core educational network 2026"
```

Security class: roughly a 128-bit group, with generic classical attack cost around `2^64` group operations.
