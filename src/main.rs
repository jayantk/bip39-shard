use anyhow::Result;
use anyhow::anyhow;

fn main() {
    let matches = clap::Command::new("seed-splitter")
        .about("Split a BIP39 seed phrase into Shamir shares")
        .subcommand(
            clap::Command::new("split")
                .about("Split a seed phrase into multiple shards")
                .arg(
                    clap::Arg::new("seed-phrase")
                        .help("The seed phrase to split")
                        .required(true)
                )
                .arg(
                    clap::Arg::new("shards")
                        .short('n')
                        .long("shards")
                        .help("Number of shards to create (minimum 2)")
                        .required(true)
                        .value_parser(clap::value_parser!(u8).range(2..))
                )
                .arg(
                    clap::Arg::new("threshold")
                        .short('t')
                        .long("threshold")
                        .help("Number of shards required to recover the secret (minimum 2, maximum: number of shards)")
                        .required(true)
                        .value_parser(clap::value_parser!(u8).range(2..))
                ),
        )
        .subcommand(
            clap::Command::new("recover")
                .about("Recover the original seed phrase from shards")
                .arg(
                    clap::Arg::new("shards")
                        .help("The shards to recover from (one per line)")
                        .required(true)
                        .num_args(1..)
                )
        )
        .get_matches();

    match matches.subcommand() {
        Some(("split", matches)) => {
            let seed_phrase = matches.get_one::<String>("seed-phrase").unwrap().clone();
            let num_shards = *matches.get_one::<u8>("shards").unwrap();
            let threshold = *matches.get_one::<u8>("threshold").unwrap();
            
            if let Err(e) = split_command(&seed_phrase, num_shards, threshold) {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
        Some(("recover", matches)) => {
            let shards: Vec<MnemonicShard> = matches
                .get_many::<String>("shards")
                .unwrap()
                .map(|s| {
                    let parts: Vec<&str> = s.split_whitespace().collect();
                    if parts.len() < 2 {
                        eprintln!("Invalid shard format. Expected: <number> <mnemonic>");
                        std::process::exit(1);
                    }
                    let index = parts[0].parse::<u8>().unwrap_or_else(|_| {
                        eprintln!("Invalid shard number");
                        std::process::exit(1);
                    });
                    let mnemonic = bip39::Mnemonic::parse_in(
                        bip39::Language::English,
                        &parts[1..].join(" ")
                    ).unwrap_or_else(|e| {
                        eprintln!("Invalid mnemonic: {}", e);
                        std::process::exit(1);
                    });
                    MnemonicShard {
                        index,
                        mnemonic,
                    }
                })
                .collect();
            match recover_command(&shards) {
                Ok(phrase) => {
                    println!("Recovered seed phrase: {}", phrase);
                }
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("Unknown command");
            std::process::exit(1);
        }
    };    
}

#[derive(Clone, Debug)]
struct MnemonicShard {
    pub index: u8,
    pub mnemonic: bip39::Mnemonic,
}

fn split_command(seed_phrase: &str, num_shards: u8, threshold: u8) -> Result<Vec<MnemonicShard>> {
    // Validate threshold is not greater than number of shards
    if threshold > num_shards {
        return Err(anyhow!("Threshold cannot be greater than the number of shards"));
    }

    // Convert seed phrase to entropy bytes
    let entropy = bip39::Mnemonic::parse_in(bip39::Language::English, seed_phrase)
        .map_err(|e| anyhow!("Invalid seed phrase: {}", e))?
        .to_entropy();

    // Create Shamir shards
    let shares = sharks::Sharks(threshold).dealer(&entropy).take(num_shards as usize);

    // Convert each shard back to a BIP39 phrase and collect into Vec
    let mut mnemonics = Vec::new();
    for share in shares {
        let share_bytes: Vec<u8> = share.y.iter().map(|b| b.0).collect();
        let mnemonic = bip39::Mnemonic::from_entropy(&share_bytes)
            .map_err(|e| anyhow!("Failed to convert shard {} to phrase: {}", share.x.0, e))?;
        println!("Shard {}: {} {}", share.x.0, share.x.0, mnemonic.to_string());
        mnemonics.push(MnemonicShard {
            index: share.x.0,
            mnemonic,
        });
    }
    Ok(mnemonics)
}

fn recover_command(shards: &[MnemonicShard]) -> Result<String> {
    // Convert BIP39 phrases back to bytes
    let mut shares = Vec::new();
    for shard in shards {
        let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, &shard.mnemonic.to_string())
            .map_err(|e| anyhow!("Invalid shard {}: {}", shard.index, e))?;

        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(shard.index);
        bytes.extend(mnemonic.to_entropy().iter().map(|b| *b));
        let share = sharks::Share::try_from(bytes.as_slice()).map_err(|e| anyhow!("Failed to convert shard bytes: {}", e))?;
        shares.push(share);
    }

    // Recover the original secret
    let recovered = sharks::Sharks(shares.len() as u8)
        .recover(&shares)
        .map_err(|e| anyhow!("Failed to recover secret: {}", e))?;

    // Convert recovered bytes back to seed phrase
    let mnemonic = bip39::Mnemonic::from_entropy(&recovered)
        .map_err(|e| anyhow!("Failed to convert recovered secret to phrase: {}", e))?;
    
    Ok(mnemonic.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn test_shard_recover_roundtrip(secret_bytes: SecretBytes) -> bool {
        let secret_bytes = secret_bytes.0;
        println!("Secret bytes: {:?}", secret_bytes);
        // Create BIP39 mnemonic from secret
        let original_mnemonic = match bip39::Mnemonic::from_entropy(&secret_bytes) {
            Ok(m) => m,
            Err(e) => {
                println!("Error: {}", e);
                return true // Skip invalid entropy
            }
        };
        let original_phrase = original_mnemonic.to_string();
        println!("Original: {}", original_phrase);

        // Split into shards using the existing function
        let shards = match split_command(&original_phrase, 5, 3) {
            Ok(s) => s,
            Err(e) => {
                println!("Error: {}", e);
                return false
            }
        };
        println!("Shards: {:?}", shards);

        // Recover using just 3 shards
        let recovered_phrase = match recover_command(&shards[0..3].to_vec()) {
            Ok(p) => p,
            Err(e) => {
                println!("Error: {}", e);
                return false
            }
        };
        println!("Recovered: {}", recovered_phrase);

        // Compare original and recovered phrases
        original_phrase == recovered_phrase
    }

    #[derive(Clone, Debug)]
    struct SecretBytes([u8; 32]);

    impl quickcheck::Arbitrary for SecretBytes {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let mut arr = [0u8; 32];
            for byte in arr.iter_mut() {
                *byte = u8::arbitrary(g);
            }
            SecretBytes(arr)
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            let vec: Vec<u8> = self.0.to_vec();
            Box::new(vec.shrink()
                .filter(|v| v.len() == 32)
                .map(|v| {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&v);
                    SecretBytes(arr)
                }))
        }
    }
}
