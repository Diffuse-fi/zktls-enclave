// Declare the mock_lib as an external crate, since it contains OCALL which will be called by the enclave.
// The automata_sgx_sdk will link the `untrusted_execution` OCALL to the mock_lib.
use clap::{Arg, Command};
extern crate mock_lib;

use automata_sgx_sdk::types::SgxStatus;

//Enclave definition. Used by the automata_sgx_sdk.
automata_sgx_sdk::enclave! {
    name: Enclave,
    ecall: {
        fn trusted_execution(file_path_ptr: *const u8, file_path_len: u32) -> SgxStatus;
    }
}

/**
 * This is the entry point of the app.
 * It creates a new enclave(in debug mode) and calls the trusted_execution function.
 */
fn main() {
    println!("=============== Starting the app =================");

    let matches = Command::new("my_app")
        .arg(
            Arg::new("pairs_file_path")
                .long("pairs_file_path")
                .required(true)
                .help("Path to the file with pairs")
                .num_args(1)
        )
        .get_matches();

    let pairs_file_path = matches
        .get_one::<String>("pairs_file_path")
        .expect("Required parameter not found");

    println!("Path to the pairs file: {}", pairs_file_path);
    
    let mut path_bytes = pairs_file_path.clone().into_bytes();
    path_bytes.push(0);
    
    let result = Enclave::new().trusted_execution(
        path_bytes.as_ptr(),
        path_bytes.len() as u32
    ).unwrap();
    if !result.is_success() {
        println!("{:?}", result);
    }
    println!("=============== End of the app =================");
}
