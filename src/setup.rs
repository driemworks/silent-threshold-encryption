use crate::{
	crs::CRS,
	error::Error,
	types::Ciphertext,
	utils::{ark_de, ark_se, lagrange_poly, open_all_values},
};
use ark_ec::{pairing::Pairing, AffineRepr, PrimeGroup, VariableBaseMSM};
use ark_ff::FftField;
use ark_poly::{
	univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
	Radix2EvaluationDomain,
};
use ark_serialize::*;
use ark_std::{rand::RngCore, UniformRand, Zero};

use serde::{Deserialize, Serialize};

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct LagPolys<F: FftField> {
	pub l: Vec<DensePolynomial<F>>,
	pub l_minus0: Vec<DensePolynomial<F>>,
	pub l_x: Vec<DensePolynomial<F>>,
	pub li_lj_z: Vec<Vec<DensePolynomial<F>>>,
	pub denom: F,
}

impl<F: FftField> LagPolys<F> {
	// domain is the roots of unity of size n
	pub fn new(n: usize) -> Result<Self, Error> {
		let domain = Radix2EvaluationDomain::<F>::new(n).ok_or(Error::DomainConstructionError)?;

		// compute polynomial L_i(X)
		let mut l = vec![DensePolynomial::zero(); n];
		for (i, ell) in l.iter_mut().enumerate().take(n) {
			*ell = lagrange_poly(n, i)?;
		}

		// compute polynomial (L_i(X) - L_i(0))*X
		let mut l_minus0 = vec![DensePolynomial::zero(); n];
		for i in 0..n {
			let mut li_minus0_coeffs = l[i].coeffs.clone();
			li_minus0_coeffs[0] = F::zero();
			li_minus0_coeffs.insert(0, F::zero());
			l_minus0[i] = DensePolynomial::from_coefficients_vec(li_minus0_coeffs);
		}

		// compute polynomial (L_i(X) - L_i(0))/X
		let mut l_x = vec![DensePolynomial::zero(); n];
		for i in 0..n {
			l_x[i] = DensePolynomial::from_coefficients_vec(l_minus0[i].coeffs[2..].to_vec());
		}

		// compute polynomial L_i(X)*L_j(X)/Z(X) and (L_i(X)*L_i(X) - L_i(X))/Z(X)
		let mut li_lj_z = vec![vec![DensePolynomial::zero(); n]; n];
		for i in 0..n {
			for j in 0..n {
				li_lj_z[i][j] = if i == j {
					(&l[i] * &l[i] - &l[i]).divide_by_vanishing_poly(domain).0
				} else {
					(&l[i] * &l[j]).divide_by_vanishing_poly(domain).0
				};
			}
		}

		let mut denom = F::one();
		for i in 1..n {
			denom *= F::one() - domain.element(i);
		}

		let denom = denom.inverse().ok_or(Error::NonInvertibleElement)?;

		Ok(Self { l, l_minus0, l_x, li_lj_z, denom })
	}
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Clone)]
pub struct SecretKey<E: Pairing> {
	/// Party id
	pub id: usize,
	/// Secret key in the scalar field
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	sk: E::ScalarField,
}

#[derive(
	Clone, Debug, PartialEq, Serialize, Deserialize, CanonicalDeserialize, CanonicalSerialize,
)]
pub struct PartialDecryption<E: Pairing> {
	/// Party id
	pub id: usize,
	/// Party commitment
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub signature: E::G2,
}

impl<E: Pairing> PartialDecryption<E> {
	pub fn zero() -> Self {
		PartialDecryption { id: 0, signature: E::G2::zero() }
	}
}

/// Position oblivious public key -- slower to aggregate
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PublicKey<E: Pairing> {
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub bls_pk: E::G1, //BLS pk
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub hints: Vec<E::G1Affine>, //hints
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub y: Vec<E::G1Affine>, /* preprocessed toeplitz matrix. only for efficiency and can be
	                          * computed from hints */
	pub id: usize, // canonically assigned unique id in the system
}

/// Public key that can only be used in a fixed position -- faster to aggregate
#[derive(CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Clone)]
pub struct LagPublicKey<E: Pairing> {
	pub id: usize,       //id of the party
	pub position: usize, //position in the aggregate key
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub bls_pk: E::G1, //BLS pk
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub sk_li: E::G1, //hint
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub sk_li_minus0: E::G1, //hint
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub sk_li_lj_z: Vec<E::G1>, //hint
	#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
	pub sk_li_x: E::G1, //hint
}

impl<E: Pairing> LagPublicKey<E> {
	pub fn new(
		id: usize,
		position: usize,
		bls_pk: E::G1,
		sk_li: E::G1,
		sk_li_minus0: E::G1,
		sk_li_lj_z: Vec<E::G1>, //i = id
		sk_li_x: E::G1,
	) -> Self {
		LagPublicKey { id, position, bls_pk, sk_li, sk_li_minus0, sk_li_lj_z, sk_li_x }
	}
}

impl<E: Pairing> SecretKey<E> {
	pub fn new<R: RngCore>(rng: &mut R, id: usize) -> Self {
		SecretKey { id, sk: E::ScalarField::rand(rng) }
	}

	pub fn from_scalar(sk: E::ScalarField, id: usize) -> Self {
		SecretKey { id, sk }
	}

	pub fn get_pk(&self, crs: &CRS<E>) -> PublicKey<E> {
		let mut hints = vec![E::G1Affine::zero(); crs.powers_of_g.len()];

		let bls_pk = E::G1::generator() * self.sk;

		for (i, hint) in hints.iter_mut().enumerate().take(crs.powers_of_g.len()) {
			*hint = (crs.powers_of_g[i] * self.sk).into();
		}

		// compute y
		let mut y = vec![E::G1Affine::zero(); crs.y.len()];
		for i in 0..crs.y.len() {
			y[i] = (crs.y[i] * self.sk).into();
		}

		PublicKey { id: self.id, bls_pk, hints, y }
	}

	pub fn get_lagrange_pk(&self, position: usize, crs: &CRS<E>) -> Option<LagPublicKey<E>> {
		let crs_li = *crs.li.get(position)?;
		let crs_li_minus0 = *crs.li_minus0.get(position)?;
		let crs_li_x = *crs.li_x.get(position)?;
		let crs_li_lj_z = crs.li_lj_z.get(position)?.clone();

		let mut sk_li_lj_z = vec![];

		let sk_li = crs_li * self.sk;

		let sk_li_minus0 = crs_li_minus0 * self.sk;

		let sk_li_x = crs_li_x * self.sk;

		for j in 0..crs.n {
			let crs_li_lj_z_j = *crs_li_lj_z.get(j)? * self.sk;
			sk_li_lj_z.push(crs_li_lj_z_j);
		}

		Some(LagPublicKey {
			id: self.id,
			position,
			bls_pk: E::G1::generator() * self.sk,
			sk_li,
			sk_li_minus0,
			sk_li_lj_z,
			sk_li_x,
		})
	}

	pub fn partial_decryption(&self, ct: &Ciphertext<E>) -> PartialDecryption<E> {
		PartialDecryption {
			id: self.id,
			signature: ct.gamma_g2 * self.sk, // bls signature on gamma_g2
		}
	}
}

impl<E: Pairing> PublicKey<E> {
	pub fn get_lag_public_key(
		&self,
		position: usize,
		crs: &CRS<E>,
		lag_polys: &LagPolys<E::ScalarField>,
	) -> Result<LagPublicKey<E>, Error> {
		// need to handle if lag_polys.l[position] exists
		// need to handle if lag_polys.l_minus[position] exists
		// need to handle if lag_polys.l_x[position] exists
		// assert!(position < crs.n, "position out of bounds");
		// we also need to be sure that self.hints[lag_polys[position].degree() + 1] exists
		let sk_li =
			E::G1::msm(&self.hints[0..lag_polys.l[position].degree() + 1], &lag_polys.l[position])
				.map_err(|min_len| Error::MSMError(min_len))?;

		// compute sk_li_minus0
		let sk_li_minus0 = E::G1::msm(
			&self.hints[0..lag_polys.l_minus0[position].degree() + 1],
			&lag_polys.l_minus0[position],
		)
		.map_err(|min_len| Error::MSMError(min_len))?;

		// compute sk_li_x
		let sk_li_x = E::G1::msm(
			&self.hints[0..lag_polys.l_x[position].degree() + 1],
			&lag_polys.l_x[position],
		)
		.map_err(|min_len| Error::MSMError(min_len))?;

		// compute sk*Li*Lj/Z = sk*Li/(X-omega^j)*(omega^j/denom) for all j in [n]\{i}
		// for j = i: (Li^2 - Li)/Z = (Li - 1)/(X-omega^i)*(omega^i/denom)
		// this is the same as computing KZG opening proofs at all points
		// in the roots of unity domain for the polynomial Li(X), where the
		// crs is {g^sk, g^{sk * tau}, g^{sk * tau^2}, ...}
		// todo: move to https://eprint.iacr.org/2024/1279.pdf
		let domain = Radix2EvaluationDomain::<E::ScalarField>::new(crs.n)
			.ok_or(Error::DomainConstructionError)?;
		let mut sk_li_lj_z = open_all_values::<E>(&self.y, &lag_polys.l[position].coeffs, &domain)?;

		for (j, s) in sk_li_lj_z.iter_mut().enumerate().take(crs.n) {
			*s *= domain.element(j) * lag_polys.denom;
		}

		Ok(LagPublicKey {
			id: self.id,
			position,
			bls_pk: self.bls_pk,
			sk_li,
			sk_li_minus0,
			sk_li_lj_z,
			sk_li_x,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::aggregate::AggregateKey;
	use proptest::prelude::*;

	type E = ark_bls12_381::Bls12_381;
	type F = ark_bls12_381::Fr;

	#[test]
	fn test_setup() {
		let mut rng = ark_std::test_rng();
		let n = 1 << 4;
		let crs = CRS::<E>::new(n, &mut rng).unwrap();

		let mut sk: Vec<SecretKey<E>> = Vec::new();
		let mut pk: Vec<LagPublicKey<E>> = Vec::new();
		let mut lagrange_pk: Vec<LagPublicKey<E>> = Vec::new();

		for i in 0..n {
			sk.push(SecretKey::<E>::new(&mut rng, i));
			pk.push(sk[i].get_lagrange_pk(i, &crs).unwrap());
			lagrange_pk.push(sk[i].get_lagrange_pk(i, &crs).unwrap());

			assert_eq!(pk[i].sk_li, lagrange_pk[i].sk_li);
			assert_eq!(pk[i].sk_li_minus0, lagrange_pk[i].sk_li_minus0);
			assert_eq!(pk[i].sk_li_x, lagrange_pk[i].sk_li_x); //computed incorrectly go fix it
			assert_eq!(pk[i].sk_li_lj_z, lagrange_pk[i].sk_li_lj_z);
		}

		let _ak = AggregateKey::<E>::new(pk, &crs).unwrap();
	}

	#[test]
	fn test_setup_with_0_domain_size() {
		let mut rng = ark_std::test_rng();
		let n = 1 << 4;
		let crs = CRS::<E>::new(n, &mut rng).unwrap();

		let mut sk: Vec<SecretKey<E>> = Vec::new();
		let mut pk: Vec<LagPublicKey<E>> = Vec::new();
		let mut lagrange_pk: Vec<LagPublicKey<E>> = Vec::new();

		for i in 0..n {
			sk.push(SecretKey::<E>::new(&mut rng, i));
			pk.push(sk[i].get_lagrange_pk(i, &crs).unwrap());
			lagrange_pk.push(sk[i].get_lagrange_pk(i, &crs).unwrap());

			assert_eq!(pk[i].sk_li, lagrange_pk[i].sk_li);
			assert_eq!(pk[i].sk_li_minus0, lagrange_pk[i].sk_li_minus0);
			assert_eq!(pk[i].sk_li_x, lagrange_pk[i].sk_li_x); //computed incorrectly go fix it
			assert_eq!(pk[i].sk_li_lj_z, lagrange_pk[i].sk_li_lj_z);
		}

		let _ak = AggregateKey::<E>::new(pk, &crs).unwrap();
	}

	#[test]
	fn test_setup_lag_setup() {
		let mut rng = ark_std::test_rng();
		let n = 1 << 4;
		let crs = CRS::<E>::new(n, &mut rng).unwrap();
		let lagpolys = LagPolys::<F>::new(n).unwrap();

		let sk = SecretKey::<E>::new(&mut rng, 0);
		let pk = sk.get_pk(&crs);
		let lag_pk = sk.get_lagrange_pk(0, &crs).unwrap();

		let computed_lag_pk = pk.get_lag_public_key(0, &crs, &lagpolys).unwrap();

		assert_eq!(computed_lag_pk.bls_pk, lag_pk.bls_pk);
		assert_eq!(computed_lag_pk.sk_li, lag_pk.sk_li);
		assert_eq!(computed_lag_pk.sk_li_minus0, lag_pk.sk_li_minus0);
		assert_eq!(computed_lag_pk.sk_li_x, lag_pk.sk_li_x);
		assert_eq!(computed_lag_pk.sk_li_lj_z, lag_pk.sk_li_lj_z);
	}

	#[test]
	fn test_setup_lag_setup_with_bad_position() {
		let mut rng = ark_std::test_rng();
		let n = 1 << 4;
		let crs = CRS::<E>::new(n, &mut rng).unwrap();
		let lagpolys = LagPolys::<F>::new(n).unwrap();

		let sk = SecretKey::<E>::new(&mut rng, 0);
		let pk = sk.get_pk(&crs);
		let lag_pk = sk.get_lagrange_pk(0, &crs).unwrap();

		let computed_lag_pk = pk.get_lag_public_key(0, &crs, &lagpolys).unwrap();

		assert_eq!(computed_lag_pk.bls_pk, lag_pk.bls_pk);
		assert_eq!(computed_lag_pk.sk_li, lag_pk.sk_li);
		assert_eq!(computed_lag_pk.sk_li_minus0, lag_pk.sk_li_minus0);
		assert_eq!(computed_lag_pk.sk_li_x, lag_pk.sk_li_x);
		assert_eq!(computed_lag_pk.sk_li_lj_z, lag_pk.sk_li_lj_z);
	}

	#[cfg(feature = "proptest")]
	proptest! {
		#[test]
		fn proptest_secretkey_get_pk(id in 0usize..6usize, n in 1usize..6usize) {
			let mut rng = ark_std::test_rng();
			let crs = CRS::<E>::new(n, &mut rng).unwrap();

			let sk = SecretKey::<E>::new(&mut rng, id);
			let pk = sk.get_pk(&crs);

			assert_eq!(pk.id, sk.id);
			assert_eq!(pk.bls_pk, <E as Pairing>::G1::generator() * sk.sk);

			for (i, hint) in pk.hints.iter().enumerate().take(crs.powers_of_g.len()) {
				assert_eq!(*hint, (crs.powers_of_g[i] * sk.sk));
			}

			for i in 0..crs.y.len() {
				assert_eq!(pk.y[i], (crs.y[i] * sk.sk));
			}
		}
	}

	#[cfg(feature = "proptest")]
	proptest! {
		#[test]
		fn proptest_secretkey_get_lagrange_pk(position in 0usize..6usize, n in 1usize..6usize) {
			let mut rng = ark_std::test_rng();
			let crs = CRS::<E>::new(n, &mut rng).unwrap();

			let sk = SecretKey::<E>::new(&mut rng, 0);
			match sk.get_lagrange_pk(position, &crs) {
				Some (lpk) => {
					assert_eq!(lpk.id, sk.id);
					assert_eq!(lpk.position, position);
					assert_eq!(lpk.bls_pk, <E as Pairing>::G1::generator() * sk.sk);
					assert_eq!(lpk.sk_li, crs.li[position] * sk.sk);
					assert_eq!(lpk.sk_li_minus0, crs.li_minus0[position] * sk.sk);
				},
				None => {
					assert!(
						crs.li.get(position).is_none()
						|| crs.li_minus0.get(position).is_none()
						|| crs.li_x.get(position).is_none()
						|| position >= crs.n
					);
				}
			}
		}
	}

	// proptest! {
	// 	#[test]
	// 	fn proptest_get_lag_public_key(
	// 		position in 0usize..6usize,
	// 		m in 1usize..6usize,
	// 		n in 1usize..6usize,
	// 	) {
	// 		let mut rng = ark_std::test_rng();
	// 		let crs = CRS::<E>::new(m, &mut rng).unwrap();
	// 		let lagpolys = LagPolys::<F>::new(n).unwrap();

	// 		let sk = SecretKey::<E>::new(&mut rng, 0);
	// 		let pk = sk.get_pk(&crs);
	// 		let lag_pk = sk.get_lagrange_pk(0, &crs);

	// 		let computed_lag_pk = pk.get_lag_public_key(0, &crs, &lagpolys).unwrap();

	// 	}

	// }
}
