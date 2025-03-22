use enum_map::{Enum, EnumArray, EnumMap};
use hashbrown::HashMap;
use sp1_sdk::ExecutionReport;
use tabled::{Table, Tabled};

pub struct Report(ExecutionReport);

impl Report {
    pub fn from_execution_report(report: ExecutionReport) -> Self {
        Self(report)
    }
}

#[derive(Enum, Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    ADD,
    SUB,
    XOR,
    OR,
    AND,
    SLL,
    SRL,
    SRA,
    SLT,
    SLTU,
    MUL,
    MULH,
    MULHU,
    MULHSU,
    DIV,
    DIVU,
    REM,
    REMU,
    LB,
    LH,
    LW,
    LBU,
    LHU,
    SB,
    SH,
    SW,
    BEQ,
    BNE,
    BLT,
    BGE,
    BLTU,
    BGEU,
    JAL,
    JALR,
    AUIPC,
    ECALL,
    EBREAK,
    UNIMP,
}

#[allow(non_camel_case_types)]
#[derive(Enum, Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SyscallCode {
    HALT,
    WRITE,
    ENTER_UNCONSTRAINED,
    EXIT_UNCONSTRAINED,
    SHA_EXTEND,
    SHA_COMPRESS,
    ED_ADD,
    ED_DECOMPRESS,
    KECCAK_PERMUTE,
    SECP256K1_ADD,
    SECP256K1_DOUBLE,
    SECP256K1_DECOMPRESS,
    BN254_ADD,
    BN254_DOUBLE,
    COMMIT,
    COMMIT_DEFERRED_PROOFS,
    VERIFY_SP1_PROOF,
    BLS12381_DECOMPRESS,
    HINT_LEN,
    HINT_READ,
    UINT256_MUL,
    U256XU2048_MUL,
    BLS12381_ADD,
    BLS12381_DOUBLE,
    BLS12381_FP_ADD,
    BLS12381_FP_SUB,
    BLS12381_FP_MUL,
    BLS12381_FP2_ADD,
    BLS12381_FP2_SUB,
    BLS12381_FP2_MUL,
    BN254_FP_ADD,
    BN254_FP_SUB,
    BN254_FP_MUL,
    BN254_FP2_ADD,
    BN254_FP2_SUB,
    BN254_FP2_MUL,
    SECP256R1_ADD,
    SECP256R1_DOUBLE,
    SECP256R1_DECOMPRESS,
}

#[derive(Tabled)]
struct KeyValue {
    key: String,
    value: u64,
}

impl Report {
    pub fn print_table(&self) {
        let opcode_table = self.create_enum_table("Opcode Counts", &self.0.opcode_counts);
        let syscall_table = self.create_enum_table("Syscall Counts", &self.0.syscall_counts);
        let cycle_table = self.create_hashmap_table("Cycle Tracker", &self.0.cycle_tracker);
        let invocation_table =
            self.create_hashmap_table("Invocation Tracker", &self.0.invocation_tracker);

        println!("{}", opcode_table);
        println!("{}", syscall_table);
        println!("{}", cycle_table);
        println!("{}", invocation_table);
        println!(
            "Touched Memory Addresses: {}\nGas Used: {}\n",
            self.0.touched_memory_addresses,
            self.0.gas.unwrap_or(0)
        );
    }

    fn create_enum_table<T: EnumArray<u64> + std::fmt::Debug>(
        &self,
        title: &str,
        map: &EnumMap<T, u64>,
    ) -> String {
        let rows: Vec<KeyValue> = map
            .iter()
            .map(|(k, &v)| KeyValue {
                key: format!("{:?}", k),
                value: v,
            })
            .collect();

        let table = Table::new(rows);
        format!("\n{}\n{}", title, table)
    }

    fn create_hashmap_table(&self, title: &str, map: &HashMap<String, u64>) -> String {
        let rows: Vec<KeyValue> = map
            .iter()
            .map(|(k, &v)| KeyValue {
                key: k.clone(),
                value: v,
            })
            .collect();

        let table = Table::new(rows);
        format!("\n{}\n{}", title, table)
    }
}
