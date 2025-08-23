use crate::{aggregate::EncryptionKey, crs::CRS, error::Error, types::Ciphertext};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit};
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_serialize::*;
use ark_std::UniformRand;
use hkdf::Hkdf;
use sha2::Sha256;
use std::ops::Mul;
use subtle::Choice;

type CryptoResult<T> = Result<T, Error>;

/// t is the threshold for encryption and apk is the aggregated public key
pub fn encrypt<E: Pairing>(
	ek: &EncryptionKey<E>,
	t: usize,
	crs: &CRS<E>,
	gamma_g2: E::G2, // this should be hash_to_point(attestation_data)
	m: &[u8],
) -> CryptoResult<Ciphertext<E>> {
	// TODO: replace the rng
	let mut rng = ark_std::test_rng();
	// CRS is public -> fail early
	// why is poh < 3?
	if crs.powers_of_g.len() <= t || crs.powers_of_h.len() < 3 {
		return Err(Error::InvalidCRS);
	}

	let g = crs.powers_of_g[0];
	let g_t = crs.powers_of_g[t];
	let h = crs.powers_of_h[0];
	let h_1 = crs.powers_of_h[1];
	let h_2 = crs.powers_of_h[2];

	let mut sa1 = [E::G1::generator(); 2];
	let mut sa2 = [E::G2::generator(); 6];

	// hazardous beyond this point
	// Generate random scalars - this is fine to collect since it's not secret-dependent timing
	let s = (0..5).map(|_| E::ScalarField::rand(&mut rng)).collect::<Vec<_>>();

	// sa1[0] = s0*ask + s3*g^{tau^{t}} + s4*g
	sa1[0] = (ek.ask * s[0]) + (g_t * s[3]) + (g * s[4]);
	// sa1[1] = s2*g
	sa1[1] = g * s[2];
	// sa2[0] = s0*h + s2*gamma_g2
	sa2[0] = (h * s[0]) + (gamma_g2 * s[2]);
	// sa2[1] = s0*z_g2
	sa2[1] = ek.z_g2 * s[0];
	// sa2[2] = s0*h^tau + s1*h^{tau^2}
	sa2[2] = h_1 * s[0] + h_2 * s[1];
	// sa2[3] = s1*h
	sa2[3] = h * s[1];
	// sa2[4] = s3*h
	sa2[4] = h * s[3];
	// sa2[5] = s4*h^{tau}
	sa2[5] = h_1 * s[4];
	// enc_key = s4*e_gh
	let enc_key = ek.e_gh.mul(s[4]);
	let mut success = Choice::from(1);
	// TODO: zeroize all three
	let mut enc_key_bytes = Vec::new();
	let mut aes_key = [0u8; 32];
	let mut aes_nonce = [0u8; 12];
	// how do we test this line?! also will thiserror still take care of it?
	let res = enc_key.serialize_compressed(&mut enc_key_bytes);
	success &= Choice::from(res.is_ok() as u8);
	// derive an encapsulation key from enc_key using an HKDF
	let hk = Hkdf::<Sha256>::new(None, &enc_key_bytes);
	// TODO: how to test?
	let res = hk.expand(&[1], &mut aes_key);
	success &= Choice::from(res.is_ok() as u8);

	let res = hk.expand(&[2], &mut aes_nonce);
	success &= Choice::from(res.is_ok() as u8);
	// encrypt the message m using the derived key
	let aes_key: &Key<Aes256Gcm> = &aes_key.into();
	let cipher = Aes256Gcm::new(aes_key);
	let ct_res = cipher.encrypt(&aes_nonce.into(), m).map_err(|_| Error::EncryptionError);
	success &= Choice::from(ct_res.is_ok() as u8);

	if success.into() {
		let aes_ct = ct_res.unwrap_or_else(|_| Vec::new());
		let ct = Ciphertext { gamma_g2, sa1, sa2, ct: aes_ct, t };
		return Ok(ct);
	}

	Err(Error::EncryptionError)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		aggregate::AggregateKey,
		crs::CRS,
		setup::{LagPublicKey, SecretKey},
	};
	use ark_std::Zero;
	use proptest::prelude::*;

	type E = ark_bls12_381::Bls12_381;
	type G1 = <E as Pairing>::G1;
	type G2 = <E as Pairing>::G2;

	const MSG: &[u8] = b"Hello, world!";

	#[test]
	fn test_encryption() {
		let mut rng = ark_std::test_rng();
		let n = 4;
		let t = 4;
		let crs = CRS::new(n, &mut rng).unwrap();

		let mut sk: Vec<SecretKey<E>> = Vec::new();
		let mut pk: Vec<LagPublicKey<E>> = Vec::new();

		for i in 0..n {
			sk.push(SecretKey::<E>::new(&mut rng, i));
			pk.push(sk[i].get_lagrange_pk(i, &crs))
		}

		let (_ak, ek) = AggregateKey::<E>::new(pk, &crs).unwrap();

		let gamma_g2 = G2::rand(&mut rng);

		let ct = encrypt::<E>(&ek, t, &crs, gamma_g2, MSG).unwrap();

		let mut ct_bytes = Vec::new();
		ct.serialize_compressed(&mut ct_bytes).unwrap();
		println!("Compressed ciphertext: {} bytes", ct_bytes.len());

		let mut g1_bytes = Vec::new();
		let mut g2_bytes = Vec::new();
		let mut e_gh_bytes = Vec::new();

		let g = G1::generator();
		let h = G2::generator();

		g.serialize_compressed(&mut g1_bytes).unwrap();
		h.serialize_compressed(&mut g2_bytes).unwrap();
		ek.e_gh.serialize_compressed(&mut e_gh_bytes).unwrap();

		println!("G1 len: {} bytes", g1_bytes.len());
		println!("G2 len: {} bytes", g2_bytes.len());
		println!("GT len: {} bytes", e_gh_bytes.len());
	}

	#[test]
	fn test_encryption_fails_with_too_small_powers_of_h() {
		let mut rng = ark_std::test_rng();
		let n = 3;
		let mut crs = CRS::new(n, &mut rng).unwrap();

		let mut sk: Vec<SecretKey<E>> = Vec::new();
		let mut pk: Vec<LagPublicKey<E>> = Vec::new();

		for i in 0..n {
			sk.push(SecretKey::<E>::new(&mut rng, i));
			pk.push(sk[i].get_lagrange_pk(i, &crs))
		}

		let (_ak, ek) = AggregateKey::<E>::new(pk, &crs).unwrap();
		let gamma_g2 = G2::zero();

		// 0 sized
		crs.powers_of_h = vec![];
		let res = encrypt::<E>(&ek, 2, &crs, gamma_g2, MSG);
		if cfg!(debug_assertions) {
			assert!(matches!(res, Err(Error::InvalidCRS)));
		} else {
			assert!(matches!(res, Err(Error::EncryptionError)));
		}

		// 1 sized
		crs.powers_of_h = vec![G2::zero().into()];
		let res = encrypt::<E>(&ek, 2, &crs, gamma_g2, MSG);
		if cfg!(debug_assertions) {
			assert!(matches!(res, Err(Error::InvalidCRS)));
		} else {
			assert!(matches!(res, Err(Error::EncryptionError)));
		}

		// 2 sized
		crs.powers_of_h = vec![G2::zero().into(), G2::zero().into()];
		let res = encrypt::<E>(&ek, 2, &crs, gamma_g2, MSG);
		if cfg!(debug_assertions) {
			assert!(matches!(res, Err(Error::InvalidCRS)));
		} else {
			assert!(matches!(res, Err(Error::EncryptionError)));
		}

		// with enough, encryption works again
		crs.powers_of_h = vec![G2::zero().into(), G2::zero().into(), G2::zero().into()];
		let ct = encrypt::<E>(&ek, 2, &crs, gamma_g2, MSG).unwrap();

		let mut ct_bytes = Vec::new();
		ct.serialize_compressed(&mut ct_bytes).unwrap();
		println!("Compressed ciphertext: {} bytes", ct_bytes.len());

		let mut g1_bytes = Vec::new();
		let mut g2_bytes = Vec::new();
		let mut e_gh_bytes = Vec::new();

		let g = G1::generator();
		let h = G2::generator();

		g.serialize_compressed(&mut g1_bytes).unwrap();
		h.serialize_compressed(&mut g2_bytes).unwrap();
		ek.e_gh.serialize_compressed(&mut e_gh_bytes).unwrap();

		println!("G1 len: {} bytes", g1_bytes.len());
		println!("G2 len: {} bytes", g2_bytes.len());
		println!("GT len: {} bytes", e_gh_bytes.len());
	}

	#[test]
	fn test_encryption_fails_with_t_greater_than_crs_n() {
		let mut rng = ark_std::test_rng();
		let n = 3;
		let crs = CRS::new(n, &mut rng).unwrap();

		let mut sk: Vec<SecretKey<E>> = Vec::new();
		let mut pk: Vec<LagPublicKey<E>> = Vec::new();

		for i in 0..n {
			sk.push(SecretKey::<E>::new(&mut rng, i));
			pk.push(sk[i].get_lagrange_pk(i, &crs))
		}

		let (_ak, ek) = AggregateKey::<E>::new(pk, &crs).unwrap();

		let gamma_g2 = G2::rand(&mut rng);

		let res = encrypt::<E>(&ek, 22, &crs, gamma_g2, MSG);
		assert!(matches!(res, Err(Error::InvalidCRS)));
	}

	#[test]
	fn test_invalid_powers_of_g_fails() {
		let t = 3;
		let powers_len = 0;
		let mut rng = ark_std::test_rng();
		let mut crs = CRS::new(10, &mut rng).unwrap();

		let mut sk: Vec<SecretKey<E>> = Vec::new();
		let mut pk: Vec<LagPublicKey<E>> = Vec::new();

		for i in 0..3 {
			sk.push(SecretKey::<E>::new(&mut rng, i));
			pk.push(sk[i].get_lagrange_pk(i, &crs))
		}

		let (_ak, ek) = AggregateKey::<E>::new(pk, &crs).unwrap();
		let gamma_g2 = G2::rand(&mut rng);

		crs.powers_of_g = vec![G1::generator().into(); powers_len];

		let result = encrypt::<E>(&ek, t, &crs, gamma_g2, b"test");
		assert!(result.is_err());
	}

	proptest! {
		#[test]
		fn prop_encrypt_validates_powers_of_h(
			threshold in 2usize..8,
			h_powers_len in 0usize..6,
			msg in prop::collection::vec(any::<u8>(), 1..100)
		) {
			let mut rng = ark_std::test_rng();
			let n = threshold + 5; // Ensure enough for key generation
			let mut crs = CRS::new(n, &mut rng).unwrap();

			let mut sk: Vec<SecretKey<E>> = Vec::new();
			let mut pk: Vec<LagPublicKey<E>> = Vec::new();

			for i in 0..n {
				sk.push(SecretKey::<E>::new(&mut rng, i));
				pk.push(sk[i].get_lagrange_pk(i, &crs))
			}

			let (_ak, ek) = AggregateKey::<E>::new(pk, &crs).unwrap();
			let gamma_g2 = G2::zero(); // Use zero like working test

			// Manually set powers_of_h to test boundary
			crs.powers_of_h = vec![G2::zero().into(); h_powers_len];

			let result = encrypt::<E>(&ek, threshold, &crs, gamma_g2, &msg);

			if h_powers_len < 3 {
				prop_assert!(result.is_err());
				if cfg!(debug_assertions) {
					prop_assert!(matches!(result, Err(Error::InvalidCRS)));
				} else {
					prop_assert!(matches!(result, Err(Error::EncryptionError)));
				}
			} else {
				prop_assert!(result.is_ok());
			}
		}
	}

	proptest! {
		#[test]
		fn prop_encrypt_validates_threshold_vs_powers_of_g(
			threshold in 1usize..15,
			crs_n in 1usize..20
		) {
			let mut rng = ark_std::test_rng();
			let mut crs = CRS::new(crs_n.max(3), &mut rng).unwrap(); // Ensure minimum viable CRS

			// Set up keys with small fixed number to avoid complexity
			let key_count = 3.min(crs_n);
			let mut sk: Vec<SecretKey<E>> = Vec::new();
			let mut pk: Vec<LagPublicKey<E>> = Vec::new();

			for i in 0..key_count {
				sk.push(SecretKey::<E>::new(&mut rng, i));
				pk.push(sk[i].get_lagrange_pk(i, &crs))
			}

			let (_ak, ek) = AggregateKey::<E>::new(pk, &crs).unwrap();
			let gamma_g2 = G2::rand(&mut rng);

			let result = encrypt::<E>(&ek, threshold, &crs, gamma_g2, MSG);

			// Check the condition: crs.powers_of_g.len() <= t
			if crs.powers_of_g.len() <= threshold {
				prop_assert!(matches!(result, Err(Error::InvalidCRS)));
			} else {
				prop_assert!(result.is_ok());
			}
		}
	}

	// ignore for now TODO: uncomment this after updating the RNG to a CryptoRng
	// // Test: Same inputs should produce different outputs (randomness)
	// proptest! {
	// 	#[test]
	// 	fn prop_encrypt_is_probabilistic(_dummy in 0u8..1u8) {
	// 		let mut rng = ark_std::test_rng();
	// 		let n = 8;
	// 		let crs = CRS::new(n, &mut rng).unwrap();

	// 		let mut sk: Vec<SecretKey<E>> = Vec::new();
	// 		let mut pk: Vec<LagPublicKey<E>> = Vec::new();

	// 		for i in 0..n {
	// 			sk.push(SecretKey::<E>::new(&mut rng, i));
	// 			pk.push(sk[i].get_lagrange_pk(i, &crs))
	// 		}

	// 		let (_ak, ek) = AggregateKey::<E>::new(pk, &crs).unwrap();
	// 		let gamma_g2 = G2::rand(&mut rng);
	// 		let msg = b"test message";

	// 		let ct1 = encrypt::<E>(&ek, 2, &crs, gamma_g2, msg).unwrap();
	// 		let ct2 = encrypt::<E>(&ek, 2, &crs, gamma_g2, msg).unwrap();

	// 		// Ciphertexts should be different due to randomness
	// 		prop_assert_ne!(ct1.ct, ct2.ct);
	// 	}
	// }
}
