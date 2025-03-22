use alloy_sol_types::SolType;
use clap::{Parser, ValueEnum};

pub mod helpers;
pub mod table;

use sp1_sdk::{include_elf, ProverClient, SP1ProofMode, SP1Stdin};
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

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[arg(value_enum, default_value_t = ProofType::Core)]
    pub mode: ProofType,

    #[arg(long, default_value_t = false)]
    print_report: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = "envoy1084.xyz";
    let inputs = generate_inputs(domain)?;

    let args = Args::parse();

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

        proof.save("proof").expect("Failed to save proof");

        println!("Successfully generated proof!");
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }

    Ok(())
}
