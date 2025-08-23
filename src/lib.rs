// Re-export the proc macro so internal modules can use crate::masked
pub mod aggregate;
pub mod crs;
pub mod decryption;
pub mod encryption;
pub mod error;
pub mod setup;
pub mod types;
pub mod utils;

// In src/lib.rs:
pub use masked_result::masked;

#[cfg(test)]
pub mod test_utils;
