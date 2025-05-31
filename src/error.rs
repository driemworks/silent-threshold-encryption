
/// Errors that can be encountered during setup, encryption, or decryption
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The domain could not be constructed 
    DomainConstructionError,
    /// The inverse function could not be computed (was the input zero?)
    InverseComputationError,
}