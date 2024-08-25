# BTC-LTC Cross-chain Demo

An example implementation of an BTC Ordinals sales contract, which can only be unlocked by paying the seller on Litecoin. The contract is currently deployable on Bitcoin Signet, since it requires OP_CAT.

## Configure Private Key

First, we need to create a .env file with our private key, which should contain some signet funds:

```
PRIVATE_KEY="cTE..."
```

You may obtain signet funds via these faucets:
- https://signetfaucet.com/
- https://alt.signetfaucet.com
- https://x.com/babylon_chain/status/1790787732643643575

## Build

```sh
npm run build
```

## Testing Locally

```sh
npm run test
```
