// use crate::{error::Error}
// #[derive(Clone)]
// pub struct TestMaskedResult<const F: bool> {}

// impl<const F: bool> MaskedResult for TestMaskedResult<F> {
// 	// Build a new MaskedResult with the success condition being Choice::from(1)
// 	fn new() -> Self {
// 		Self {}
// 	}

// 	// Return true if
// 	fn failed(self) -> bool {
// 		F
// 	}

// 	fn update<T, E>(&mut self, _res: Result<T, E>) -> Option<T> {
// 		None
// 	}

// 	fn finalize(self) -> Result<(), Error> {
// 		if F {
// 			return Ok(());
// 		}

// 		Err(Error::EncryptionError)
// 	}
// }
