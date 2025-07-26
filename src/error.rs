/// TODO: BE CAREFUL WE DO NOT INTRODUCE SIDE CHANNEL ATTACKS!!
/// Errors that can be encountered during setup, encryption, or decryption
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
	/// The domain could not be constructed
	/// TODO: reprop errors?
	DomainConstructionError,
	/// The supplied index exceeds the upper bound
	IndexOutOfBounds,
	/// The size specified exceeds u64::MAX
	InvalidDomainSize,
	/// The value used for tau was either 0 or misformatted ?
	InvalidTau,
	/// An error occured during multiscalar multiplication
	/// "msm error: length mismatch between bases and scalars; minimum length: {}",
	MSMError(usize),
	/// The group or scalar field element is non-invertible.
	NonInvertibleElement,
}
