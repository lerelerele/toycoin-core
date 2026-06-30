# AGENTS.md

## Project

Toycoin Core / Toynet128.

Educational Bitcoin-like blockchain written in Go.

## Compatibility

Must run on:

- Windows amd64
- WSL/Linux amd64

## Binaries

Main binaries:

- toycoind
- toycoin-cli

Do not break existing CLI commands.

## Network

Network name: toynet128.

Address HRP: tn.

Valid addresses start with:

```text
tn1q

Do not use toy1 addresses.

Do not support Bitcoin mainnet/testnet addresses.

Reject or clearly mark as invalid:

1...
3...
bc1...
tb1...
Security

Never print private keys by default.

Only dumpprivkey <address> may export a private key.

createwallet must not expose priv_hex or pub_hex.

Educational goal

Teach:

UTXO
PoW
mining
wallets
address reuse
public key exposure
Kangaroo risk
why Bitcoin uses larger security margins
Next priorities
RPC stability
explorer links
address pages
walletreport
tests
Windows/WSL build scripts