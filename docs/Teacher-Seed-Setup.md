# Teacher seed node setup

This v0.2.0 gossips blocks and transactions with a Bitcoin-style inventory relay
(`inv`/`getdata`) over the RPC transport, backed by pull sync; it is not a raw
TCP P2P protocol yet. Students share one Toynet128 chain through seed nodes. See
[Networking-Gossip.md](Networking-Gossip.md).

## Seed server

```bash
toycoind -toynet128 -rpclisten=0.0.0.0 -rpcport=28443 -externaladdr=http://YOUR_SEED_HOST:28443
```

Open TCP port `28443`. `-externaladdr` is the reachable URL the seed advertises
so peers can pull announced blocks/txs (inventory relay). Students behind NAT can
omit it and still participate — they relay by pushing full data.

## Student node

```bash
toycoind -toynet128 -addnode=http://YOUR_SEED_HOST:28443
```

## Two seed nodes

Seed 1:

```bash
toycoind -toynet128 -rpclisten=0.0.0.0 -rpcport=28443 -externaladdr=http://seed1.example.org:28443 -addnode=http://seed2.example.org:28443
```

Seed 2:

```bash
toycoind -toynet128 -rpclisten=0.0.0.0 -rpcport=28443 -externaladdr=http://seed2.example.org:28443 -addnode=http://seed1.example.org:28443
```

## Important classroom note

If students mine several coinbase rewards to the same address and then spend a mature reward, immature UTXOs on that same address can later become risky because the public key has already been revealed.

For the cleanest safety demo, tell students to mine to a fresh address per block, or wait for all rewards on an address to mature before spending.
