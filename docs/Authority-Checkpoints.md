# Authority checkpoints

Toycoin uses most-work fork choice: nodes follow the chain with the most
cumulative proof of work and reorg onto a heavier branch automatically. On a
trusted classroom LAN that is enough — let the students mine and the longest
chain wins.

When a node is exposed beyond that trusted network, raw most-work is not enough:
anyone with more hash power could rewrite history. **Authority checkpoints** let
one operator (typically the teacher) pin the canonical chain with a signature.

## Model

- The authority holds a dedicated **toy128k1f keypair**, generated once and kept
  **offline**. It is a plain key for this toy network — deliberately *not* a
  real-world identity credential (national eID, etc.). Your real identity can
  vouch for the public key out of band, but the private key should never live on
  a node or be used as infrastructure signing material.
- Each node is started with the authority's **public** key. It then trusts any
  `{height, blockhash}` checkpoint signed by the matching private key.
- Fork choice treats a checkpoint as a **veto**: a chain is only eligible if it
  contains the checkpointed block at the checkpointed height. A heavier branch
  that forks below/around the checkpoint is rejected. If a node is caught on a
  now-forbidden branch, it switches to the blessed branch as soon as it has it.

Checkpoints only ever move forward (a higher height replaces a lower one); a node
never downgrades to an older checkpoint.

## Setup

1. Generate the authority key offline (run on a trusted machine, store the
   private key safely — do not put it on a node):

   ```bash
   toycoin-cli genauthoritykey
   ```

2. Start every node with the public key:

   ```bash
   toycoind -toynet128 -authoritypubkey <authority_public_key_hex>
   ```

## Publishing a checkpoint

1. Pick the block to bless and get its height and hash (e.g. `getblockchaininfo`
   → `blocks` / `bestblockhash`).

2. Sign it offline with the authority private key:

   ```bash
   toycoin-cli signcheckpoint <authority_priv_hex> <height> <blockhash>
   ```

   This prints the checkpoint JSON and a ready-to-run `submitcheckpoint` command.

3. Submit it to any one node — typically the seed (this call is public: no cookie
   needed, the signature is what authorises it). Nodes relay a new checkpoint to
   their peers and also pull it during sync, so submitting once to the seed is
   enough for the whole class to pick it up:

   ```bash
   toycoin-cli submitcheckpoint <height> <blockhash> <pubkey> <signature>
   ```

4. Verify:

   ```bash
   toycoin-cli getcheckpoint
   toycoin-cli getblockchaininfo   # shows checkpoint_height and authority_configured
   ```

## Notes

- A node with no `-authoritypubkey` ignores checkpoints entirely and runs pure
  most-work fork choice (backwards compatible).
- Checkpoints propagate automatically (pushed on first accept, pulled on sync),
  so you normally submit to the seed only.
