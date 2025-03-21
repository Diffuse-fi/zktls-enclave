extern crate mock_lib;

use automata_sgx_sdk::types::SgxStatus;
use clap::{Arg, Command};

automata_sgx_sdk::enclave! {
    name: Enclave,
    ecall: {
        fn trusted_execution(file_path_ptr: *const u8, file_path_len: usize) -> SgxStatus;
    }
}

fn main() -> anyhow::Result<()> {
    let matches = Command::new("")
        .arg(
            Arg::new("pairs-file-path")
                .long("pairs-file-path")
                .required(true)
                .help("Path to the file with pairs")
                .num_args(1),
        )
        .get_matches();

    let pairs_file_path = matches
        .get_one::<String>("pairs-file-path")
        .ok_or(anyhow::anyhow!("Required parameter not found"))?;

    println!("Path to the pairs file: {}", pairs_file_path);

    let mut path_bytes = pairs_file_path.clone().into_bytes();
    path_bytes.push(0);

    let result = Enclave::new()
        .trusted_execution(path_bytes.as_ptr(), path_bytes.len())
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    if !result.is_success() {
        println!("{:?}", result);
    }
    Ok(())
}
