extern crate mock_lib;

use automata_sgx_sdk::types::SgxStatus;

automata_sgx_sdk::enclave! {
    name: Enclave,
    ecall: {
        fn trusted_execution() -> SgxStatus;
    }
}

fn main() {
    println!("=============== Starting the zktls-pairs =================");
    let result = Enclave::new().trusted_execution().unwrap();
    if !result.is_success() {
        println!("{:?}", result);
    }
    println!("=============== End of the zktls-pairs =================");
}
