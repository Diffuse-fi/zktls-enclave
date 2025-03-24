use automata_sgx_sdk::types::SgxStatus;
use clap::Parser;

automata_sgx_sdk::enclave! {
    name: Enclave,
    ecall: {
        fn trusted_execution(file_path_ptr: *const u8, file_path_len: usize) -> SgxStatus;
    }
}

#[derive(Parser)]
#[command(author = "Diffuse labs", version = "v0", about)]
struct ZkTlsPairs {
    /// Path to the file with pairs
    #[arg(long, default_value = "pairs/list.txt")]
    pairs_file_path: String,
}

fn main() -> anyhow::Result<()> {
    let cli = ZkTlsPairs::parse();

    let path_bytes = cli.pairs_file_path.into_bytes();

    let result = Enclave::new()
        .trusted_execution(path_bytes.as_ptr(), path_bytes.len())
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    if !result.is_success() {
        println!("{:?}", result);
    }

    Ok(())
}
