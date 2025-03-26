pub mod traits {
    use std::fmt::Debug;

    pub trait Tcp: Debug {
        fn write(&mut self, data: &[u8]);
        fn read(&mut self, buffer: &mut [u8]) -> usize;
        fn get() -> Self;
    }

    pub trait File: Debug {
        fn write(&mut self, data: &[u8], filename: &str);
        fn read(&mut self, filename: &str) -> Vec<u8>;
    }

    pub trait Test: Debug {
        fn test(&self) {
            print!("Test");
        }
    }
}