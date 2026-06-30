# Toycoin Core Student Guide

## Windows

```powershell
.\toycoind.exe -toynet128
```

Open another PowerShell:

```powershell
.\toycoin-cli.exe createwallet alumno
.\toycoin-cli.exe getnewaddress
.\toycoin-cli.exe getblockchaininfo
```

## WSL / Linux

```bash
./toycoind -toynet128
```

Open another terminal:

```bash
./toycoin-cli createwallet alumno
./toycoin-cli getnewaddress
./toycoin-cli getblockchaininfo
```

## Receive and mine

```bash
ADDR=$(./toycoin-cli getnewaddress | tr -d '"')
./toycoin-cli generatetoaddress 3 "$ADDR"
./toycoin-cli getbalance
```

## Send

```bash
./toycoin-cli sendtoaddress tn1DESTINATION 10
./toycoin-cli generatetoaddress 1 "$ADDR"
```

## See security lesson

```bash
./toycoin-cli security walletreport
```
