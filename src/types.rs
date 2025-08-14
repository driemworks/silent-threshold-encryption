//! common types
use crate::{
	error::Error,
	utils::{ark_de, ark_se},
};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

#[derive(
	Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Clone, PartialEq,
)]
pub struct Ciphertext<E: Pairing> {
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub gamma_g2: E::G2,
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub sa1: [E::G1; 2],
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub sa2: [E::G2; 6],
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub ct: Vec<u8>, //encrypted message
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub t: usize, //threshold
}

impl<E: Pairing> Ciphertext<E> {
	pub fn new(gamma_g2: E::G2, sa1: [E::G1; 2], sa2: [E::G2; 6], ct: Vec<u8>, t: usize) -> Self {
		Ciphertext { gamma_g2, sa1, sa2, ct, t }
	}
}

pub trait MaskedResult {
	// Build a new MaskedREsult with the success condition being Choice::from(1)
	fn new() -> Self;
	// Return true if 
	fn failed(self) -> bool;
	/// Update the success flag based on the result, without early return
	fn update<T, E>(&mut self, res: Result<T, E>) -> Option<T>;
	/// Final check to convert masked success to Result<(), Error>
	fn finalize(self) -> Result<(), crate::error::Error>;
}

/// A helper struct for constant time error handling using subtle
#[derive(Clone)]
pub struct MaskedResultImpl {
	pub success: Choice,
}

impl MaskedResult for MaskedResultImpl {
	// Build a new MaskedREsult with the success condition being Choice::from(1)
	fn new() -> Self {
		Self { success: Choice::from(1) }
	}

	// Return true if 
	fn failed(self) -> bool {
		self.success.ct_eq(&Choice::from(0)).into()
	}

	fn update<T, E>(&mut self, res: Result<T, E>) -> Option<T> {
		match res {
			Ok(val) => Some(val),
			Err(_) => {
				self.success = Choice::from(0);
				None
			},
		}
	}

	fn finalize(self) -> Result<(), Error> {
		if self.success.ct_eq(&Choice::from(1)).into() {
			Ok(())
		} else {
			Err(crate::error::Error::EncryptionError)
		}
	}
}
