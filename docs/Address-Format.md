# Toycoin Address Format v0.1.2

Toycoin v0.1 used a provisional `toy1` + Base58Check-looking address. That has been removed because it looked like an ad-hoc prefix, not a serious Bitcoin-like address format.

Toycoin v0.1.2 uses a native Bech32 witness-v0 style address.

```text
HRP: tn
separator: 1
witness version: 0
program: ToyHash160(pubkey) = SHA256(pubkey)[:20]
checksum: 6 Bech32 characters
example: tn1q8z4h8k7k0q7vwrnvh0aqt7j7q0xp6mcmv7vx9w
```

Properties:

- Addresses start with `tn1q...`.
- Mixed case is invalid.
- Any typo should normally fail checksum validation.
- Bitcoin mainnet formats `1...`, `3...`, `bc1...` and WIF private keys are not accepted.
- The format is educational and not compatible with Bitcoin.

Migration note: v0.1 `toy1b...` addresses are obsolete. For a clean class chain, delete the old Toycoin data directory and restart Toynet128 with v0.1.2.
