//! common types
use crate::utils::{ark_de, ark_se};
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

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

impl<E: Pairing> Default for Ciphertext<E> {
	fn default() -> Ciphertext<E> {
		let g1 = E::G1::generator();
		let g2 = <E as Pairing>::G2::generator();

		Self { gamma_g2: g2, sa1: [g1; 2], sa2: [g2; 6], ct: Vec::new(), t: 0 }
	}
}

impl<E: Pairing> Ciphertext<E> {
	pub fn new(gamma_g2: E::G2, sa1: [E::G1; 2], sa2: [E::G2; 6], ct: Vec<u8>, t: usize) -> Self {
		Ciphertext { gamma_g2, sa1, sa2, ct, t }
	}
}
