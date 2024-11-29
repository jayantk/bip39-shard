# BIP39 Shard

A command-line tool for splitting BIP39 seed phrases into Shamir secret shares and recovering them.

## Features

- Split a BIP39 seed phrase into multiple shares using Shamir's Secret Sharing
- Recover the original seed phrase using a threshold number of shares
- Generate new random BIP39 seed phrases

## Usage

Generate a new random BIP39 seed phrase:

```sh
$ bip39-shard generate
pledge ridge neutral civil discover series over crowd digital panda draft devote silly tide era weekend spin bleak follow basic twice marriage trophy toast
```

Split a seed phrase into 5 shares, requiring 3 of them to recover the original phrase:

```sh
$ bip39-shard split --shards 5 --threshold 3 "pledge ridge neutral civil discover series over crowd digital panda draft devote silly tide era weekend spin bleak follow basic twice marriage trophy toast"
1 mammal worth view bullet toddler dress possible patient infant dress account secret twin apple weapon arrow seven erosion receive tourist try famous wrong fiction
2 zebra chuckle topic net blossom bundle there renew inflict fish father pen satisfy quote coconut meat original among mixed awkward where jewel theory leave
3 text hollow link perfect sheriff ocean steak casino differ media because found orient fork ocean leisure measure fresh grow tower wedding public voyage team
4 idle dance brief gold thumb display drum taste soda ocean circle bench toy trick leg result skate mobile cruel anger floor input crouch identify
5 explain industry language fault diagram rice ivory enter letter early harsh twice shield adapt slender draw tent stem tank wrestle forward purity carbon ship
```

The output of this command will be printed to stdout and list a mnemonic phrase per line, with the number of each shard prefixed.
Note that the *number of each shard* must be saved along with the mnemonic phrase itself.
The number is required to recover the original seed phrase.

Recover the original seed phrase from 3 shares:

```shards.txt
2 zebra chuckle topic net blossom bundle there renew inflict fish father pen satisfy quote coconut meat original among mixed awkward where jewel theory leave
3 text hollow link perfect sheriff ocean steak casino differ media because found orient fork ocean leisure measure fresh grow tower wedding public voyage team
5 explain industry language fault diagram rice ivory enter letter early harsh twice shield adapt slender draw tent stem tank wrestle forward purity carbon ship
```

```sh
$ cat shards.txt | bip39-shard recover
pledge ridge neutral civil discover series over crowd digital panda draft devote silly tide era weekend spin bleak follow basic twice marriage trophy toast
```