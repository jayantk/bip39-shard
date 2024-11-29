use anyhow::Result;
use anyhow::anyhow;
use std::io::{self, BufRead};

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let matches = build_cli().get_matches();

    match matches.subcommand() {
        Some(("split", matches)) => {
            let args = parse_split_args(matches)?;
            let shards = split_command(&args.seed_phrase, args.num_shards, args.threshold)?;
            for shard in shards {
                println!("{} {}", shard.index, shard.mnemonic.to_string());
            }
            Ok(())
        }
        Some(("recover", _)) => {
            let shards = parse_recover_args()?;
            let phrase = recover_command(&shards)?;
            println!("{}", phrase);
            Ok(())
        }
        Some(("generate", _)) => {
            let phrase = generate_command()?;
            println!("{}", phrase);
            Ok(())
        }
        Some((s, _)) => Err(anyhow!("Unknown command: {}", s)),
        None => Err(anyhow!("No command provided")),
    }
}

fn build_cli() -> clap::Command {
    clap::Command::new("bip39-shard")
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
                .about("Recover the original seed phrase from shards read from stdin (one per line)")
        )
        .subcommand(
            clap::Command::new("generate")
                .about("Generate a new random BIP39 seed phrase")
        )
}

struct SplitArgs {
    seed_phrase: String,
    num_shards: u8,
    threshold: u8,
}

fn parse_split_args(matches: &clap::ArgMatches) -> Result<SplitArgs> {
    Ok(SplitArgs {
        seed_phrase: matches.get_one::<String>("seed-phrase").unwrap().clone(),
        num_shards: *matches.get_one::<u8>("shards").unwrap(),
        threshold: *matches.get_one::<u8>("threshold").unwrap(),
    })
}

fn parse_recover_args() -> Result<Vec<MnemonicShard>> {
    let stdin = io::stdin();
    let mut shards = Vec::new();

    for line in stdin.lock().lines() {
        let line = line.map_err(|e| anyhow!("Error reading line: {}", e))?;

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(anyhow!("Invalid shard format. Expected: <number> <mnemonic>. Got:\n{}", line));
        }

        let index = parts[0].parse::<u8>()
            .map_err(|_| anyhow!("Invalid shard number"))?;

        let mnemonic = bip39::Mnemonic::parse_in(
            bip39::Language::English,
            &parts[1..].join(" ")
        ).map_err(|e| anyhow!("Invalid mnemonic: {}", e))?;

        shards.push(MnemonicShard {
            index,
            mnemonic,
        });
    }

    Ok(shards)
}

#[derive(Clone, Debug)]
struct MnemonicShard {
    pub index: u8,
    pub mnemonic: bip39::Mnemonic,
}

fn generate_command() -> Result<String> {
    // Generate 32 bytes of random data using system RNG
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy)
        .map_err(|e| anyhow!("Failed to generate random entropy: {}", e))?;
    
    // Convert to BIP39 mnemonic
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
        .map_err(|e| anyhow!("Failed to create mnemonic: {}", e))?;

    Ok(mnemonic.to_string())
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
