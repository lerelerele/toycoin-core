package core

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Checkpoint is a signed statement by the network authority that "the canonical
// chain has block BlockHash at Height". Nodes configured with the authority's
// public key refuse to follow (or reorg onto) any chain that does not contain
// that block at that height, no matter how much proof of work it carries.
//
// This is an educational "authority / checkpoint" overlay on top of most-work
// fork choice: on a trusted LAN nodes converge purely by work, but once an
// operator (the teacher) publishes a signed checkpoint, the blessed branch
// becomes the only acceptable canonical chain. The authority key is a plain
// toy128k1f key kept offline; it is deliberately NOT a real-world identity
// credential such as a national eID certificate.
type Checkpoint struct {
	Height    int    `json:"height"`
	BlockHash string `json:"block_hash"`
	PubKey    string `json:"pub_key"`   // authority public key (toy128k1f, 04-prefixed hex)
	Signature string `json:"signature"` // Sign(CheckpointSigningHash, authority private key)
}

// CheckpointSigningHash is the message digest an authority signs. It binds the
// checkpoint to this specific network so a signature cannot be replayed onto a
// different Toynet.
func CheckpointSigningHash(height int, blockHash string) []byte {
	msg := fmt.Sprintf("toycoin-checkpoint|%s|%d|%s", NetworkName, height, strings.ToLower(strings.TrimSpace(blockHash)))
	return DoubleSHA256([]byte(msg))
}

// SignCheckpoint produces a checkpoint signed by the given authority private key.
func SignCheckpoint(priv *big.Int, height int, blockHash string) (Checkpoint, error) {
	if height < 0 {
		return Checkpoint{}, errors.New("checkpoint height must be non-negative")
	}
	blockHash = strings.ToLower(strings.TrimSpace(blockHash))
	if blockHash == "" {
		return Checkpoint{}, errors.New("checkpoint block hash required")
	}
	P, err := PrivateToPublic(priv)
	if err != nil {
		return Checkpoint{}, err
	}
	pub, err := PublicKeyHex(P)
	if err != nil {
		return Checkpoint{}, err
	}
	sig, err := Sign(CheckpointSigningHash(height, blockHash), priv)
	if err != nil {
		return Checkpoint{}, err
	}
	return Checkpoint{Height: height, BlockHash: blockHash, PubKey: pub, Signature: sig}, nil
}

// VerifyCheckpoint checks that cp is well formed and carries a valid signature.
// When authorityPubHex is non-empty the checkpoint's key must equal it, so a
// node only trusts checkpoints from its configured authority.
func VerifyCheckpoint(cp Checkpoint, authorityPubHex string) error {
	if cp.Height < 0 || strings.TrimSpace(cp.BlockHash) == "" {
		return errors.New("malformed checkpoint")
	}
	if authorityPubHex != "" && !strings.EqualFold(strings.TrimSpace(cp.PubKey), strings.TrimSpace(authorityPubHex)) {
		return errors.New("checkpoint not signed by the configured authority key")
	}
	P, err := ParsePublicKeyHex(cp.PubKey)
	if err != nil {
		return fmt.Errorf("bad checkpoint pubkey: %w", err)
	}
	if !Verify(CheckpointSigningHash(cp.Height, cp.BlockHash), cp.Signature, P) {
		return errors.New("bad checkpoint signature")
	}
	return nil
}
