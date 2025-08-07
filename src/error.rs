use thiserror::Error;
/// TODO: BE CAREFUL WE DO NOT INTRODUCE SIDE CHANNEL ATTACKS!!
/// Errors that can be encountered during setup, encryptio1
// n, or decryption
#[derive(Debug, Error)]
pub enum Error {
	/// The domain could not be constructed
	/// TODO: reprop errors?
	#[error("The radix-2 domain could not be constructed.")]
	DomainConstructionError,
	/// An opaque encryption error occurred
	#[error("encryption error")]
	EncrytionError,
	/// hkdf failures
    #[error("hkdf error: {0}")]
    HkdfExpandError(#[from] hkdf::InvalidLength),
	/// The supplied index exceeds the upper bound
	#[error("The supplied index exceeds the upper bound")]
	IndexOutOfBounds,
	/// The size specified exceeds u64::MAX
	#[error("The size specified exceeds u64::MAX")]
	InvalidDomainSize,
	/// The value used for tau was either 0 or misformatted
	#[error("The value used for tau was either 0 or misformatted")]
	InvalidTau,
	/// An error occured during multiscalar multiplication
	/// "msm error: length mismatch between bases and scalars; minimum length: {}",
	#[error("msm error: length mismatch between bases and scalars; minimum length: {0}",)]
	MSMError(usize),
	/// The group or scalar field element is non-invertible.
	#[error("The group or scalar field element is non-invertible.",)]
	NonInvertibleElement,
	/// an element could not be serialized
	#[error("serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}
