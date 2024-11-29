# Seed Splitter

A command-line tool for splitting BIP39 seed phrases into Shamir secret shares and recovering them.

## Features

- Split a BIP39 seed phrase into multiple shares using Shamir's Secret Sharing
- Recover the original seed phrase using a threshold number of shares
- Generate new random BIP39 seed phrases
- Secure handling of sensitive data

## Usage

Generate a new random BIP39 seed phrase:

```sh
seed-splitter generate
```

Split a seed phrase into 5 shares, requiring 3 of them to recover the original phrase:

```sh
seed-splitter split --seed-phrase "..." --shards 5 --threshold 3
```

Note that the *number of each shard* must be saved along with the mnemonic phrase itself.
The number is required to recover the original seed phrase.

Recover the original seed phrase from 3 shares:

```shards.txt
1 ...
2 ...
3 ...
```

```sh
cat shards.txt | seed-splitter recover
```