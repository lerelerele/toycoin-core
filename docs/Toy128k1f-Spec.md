# toy128k1f specification

Educational curve for Toycoin Core / Toynet128.

## Warning

`toy128k1f` is not for production, money, legal signatures, identity systems, or real wallets.
It exists to teach elliptic curves, ECDSA, public-key exposure, Kangaroo/Pollard attacks, and the contrast with Bitcoin's secp256k1.

## Seed

```text
Toy128k1f for Toycoin Core educational network 2026
```

## Domain parameters

```text
p  = 0xcc3e373aa65e4fc92bfba193af40d4e7
a  = 0x0
b  = 0x7
Gx = 0xc10a8eb0ef340645a767114393fc4786
Gy = 0xa50d20b0925585547a2a396090e48f7a
n  = 0xcc3e373aa65e4fc91c93ff817b7e1259
h  = 0x1
```

Curve equation:

```text
y² = x³ + 7 mod p
```

## Educational security level

```text
n ≈ 2^127.674
sqrt(n) ≈ 2^63.837
```

So Toynet128 is meant to model the idea of a `~2^64` generic classical attack cost, while Bitcoin secp256k1 is around `~2^128`.
