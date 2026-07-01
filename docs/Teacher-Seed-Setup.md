# Teacher seed node setup

This v0.1.3 does not implement Bitcoin's full gossip protocol yet. It uses simple RPC peer sync so that students can share one Toynet128 chain through seed nodes.

## Seed server

```bash
toycoind -toynet128 -rpclisten=0.0.0.0 -rpcport=28443
```

Open TCP port `28443`.

## Student node

```bash
toycoind -toynet128 -addnode=http://YOUR_SEED_HOST:28443
```

## Two seed nodes

Seed 1:

```bash
toycoind -toynet128 -rpclisten=0.0.0.0 -rpcport=28443 -addnode=http://seed2.example.org:28443
```

Seed 2:

```bash
toycoind -toynet128 -rpclisten=0.0.0.0 -rpcport=28443 -addnode=http://seed1.example.org:28443
```

## Important classroom note

If students mine several coinbase rewards to the same address and then spend a mature reward, immature UTXOs on that same address can later become risky because the public key has already been revealed.

For the cleanest safety demo, tell students to mine to a fresh address per block, or wait for all rewards on an address to mature before spending.
