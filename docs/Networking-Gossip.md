# Networking & gossip

Toycoin nodes share one chain through a Bitcoin-style **inventory relay** on top
of the JSON-RPC transport. Blocks and transactions propagate transitively: any
node that accepts something new tells its peers, and they tell theirs.

> Transport note: messages ride on the existing HTTP JSON-RPC endpoint, not a
> raw TCP socket protocol with a `version`/`verack` handshake. A real socket
> transport is a future step (see Roadmap v0.3); the gossip *logic* below is the
> same idea Bitcoin uses.

## How it works

1. **Announce (`inv`)** — when a node accepts a new block or tx (mined, pushed,
   or pulled), it announces the item's `{type, hash}` to its peers.
2. **Pull (`getdata`)** — a peer that lacks the item fetches it with `getblock`
   or `gettx`, validates it, and applies it.
3. **Relay** — applying a *new* item announces it onward. A peer that already has
   it does not re-announce, so the flood stops (no loops).
4. **Address learning** — an `inv` carries the sender's advertised URL; receivers
   add it as a peer, so a one-directional `-addnode` link becomes a two-way mesh.

Pull-based `SyncOnce` (every 10 s) still runs as a backstop: gossip makes
propagation fast, sync guarantees a node that missed announcements catches up.

## Reachability: `-externaladdr`

Announcing inventory only helps if peers can pull from you, so a node advertises
a reachable URL:

```bash
toycoind -toynet128 -externaladdr=http://YOUR_HOST:28443
```

- **With** `-externaladdr` (e.g. the seed): the node announces `inv` and peers
  pull only what they lack — bandwidth-efficient.
- **Without** `-externaladdr` (e.g. a student behind NAT with no inbound): the
  node cannot be pulled from, so it **relays by pushing the full block/tx**
  instead. Propagation still works along the peer edges; it just uses more
  bandwidth. This is the safe default.

For a classroom seed-hub, set `-externaladdr` on the seed(s); students can leave
it unset and still participate fully.

## Related RPC methods (public, no cookie)

`inv`, `getblock`, `gettx`, `getblockchaininfo`, `submitblock`,
`submittransaction`, `submitcheckpoint`. These carry only public chain data or
fully-validated / signature-checked pushes. Wallet and key methods stay behind
cookie auth (`dumpprivkey` stays loopback-only).
