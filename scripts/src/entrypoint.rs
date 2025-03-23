use std::path::PathBuf;

use alloy_sol_types::SolType;
use clap::{Parser, ValueEnum};

pub mod helpers;
pub mod table;

use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1ProofMode, SP1Stdin};
use table::Report;
use zkdnssec_lib::PublicValuesStruct;

use helpers::generate_inputs;

pub const ZKDNSSEC_ELF: &[u8] = include_elf!("zkdnssec-program");

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum ProofType {
    Core,
    Compressed,
    Groth16,
    Plonk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1ZKDNSSECProofFixture {
    is_valid: bool,
    vkey: String,
    public_values: String,
    proof: String,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// String argument for domain
    #[arg(long, default_value = "envoy1084.xyz")]
    domain: String,

    /// Flag to execute
    #[arg(long)]
    execute: bool,

    /// Flag to prove
    #[arg(long)]
    prove: bool,

    /// Proof mode (enum)
    #[arg(value_enum, default_value_t = ProofType::Core)]
    mode: ProofType,

    /// Flag to print report
    #[arg(long)]
    print_report: bool,

    /// Flag to verify
    #[arg(long, default_value_t = false)]
    verify: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    let args = Args::parse();
    let inputs = generate_inputs(&args.domain)?;

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    sp1_sdk::utils::setup_logger();
    let client = ProverClient::from_env();

    let mut stdin = SP1Stdin::new();

    // Write Values to stdin
    // 1. Public Key
    // 2. Name
    // 3. DNSClass
    // 4. RRSIG
    // 5. Records
    // 6. Signature

    stdin.write_vec(inputs.pub_key);
    stdin.write(&inputs.name);
    stdin.write(&inputs.dns_class);
    stdin.write(&inputs.rrsig);
    stdin.write(&inputs.record);
    stdin.write_vec(inputs.signature);

    if args.execute {
        let (output, report) = client.execute(ZKDNSSEC_ELF, &stdin).run()?;
        let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true)?;

        println!("RRSIG Verified: {:#?}", decoded.is_valid);

        println!(
            "executed program with {} cycles",
            report.total_instruction_count()
        );

        if args.print_report {
            let report = Report::from_execution_report(report);
            report.print_table();
        }
    }

    if args.prove {
        let (pk, vk) = client.setup(ZKDNSSEC_ELF);

        let mode: SP1ProofMode = match args.mode {
            ProofType::Core => SP1ProofMode::Core,
            ProofType::Compressed => SP1ProofMode::Compressed,
            ProofType::Groth16 => SP1ProofMode::Groth16,
            ProofType::Plonk => SP1ProofMode::Plonk,
        };

        let proof = client
            .prove(&pk, &stdin)
            .mode(mode)
            .run()
            .expect("Failed to generate proof");

        let proof_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("./proofs");
        std::fs::create_dir_all(&proof_path).expect("failed to create proof path");

        proof
            .save(format!("proofs/{:?}-proof.bin", mode).to_lowercase())
            .expect("Failed to save proof");

        if args.mode == ProofType::Groth16 || args.mode == ProofType::Plonk {
            let bytes = proof.public_values.as_slice();
            let pub_values = PublicValuesStruct::abi_decode(bytes, false).unwrap();

            // Create the testing fixture so we can test things end-to-end.
            let fixture = SP1ZKDNSSECProofFixture {
                is_valid: pub_values.is_valid,
                vkey: vk.vk.bytes32().to_string(),
                public_values: format!("0x{}", hex::encode(bytes)),
                proof: format!("0x{}", hex::encode(proof.bytes())),
            };

            let fixture_path =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
            std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
            std::fs::write(
                fixture_path.join(format!("{:?}-fixture.json", mode).to_lowercase()),
                serde_json::to_string_pretty(&fixture).unwrap(),
            )
            .expect("failed to write fixture");
        }

        println!("Successfully generated proof!");
        if args.verify {
            client.verify(&proof, &vk).expect("failed to verify proof");
            println!("Successfully verified proof!");
        }
    }

    Ok(())
}
