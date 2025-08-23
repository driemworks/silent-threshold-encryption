use crate::{
	aggregate::EncryptionKey,
	crs::CRS,
	error::Error,
	types::Ciphertext,
};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit};
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_serialize::*;
use ark_std::UniformRand;
use hkdf::Hkdf;
use crate::masked;
use sha2::Sha256;
use std::ops::Mul;

/// t is the threshold for encryption and apk is the aggregated public key
#[masked(Error::EncryptionError)]
pub fn encrypt<E: Pairing>(
	ek: &EncryptionKey<E>,
	t: usize,
	crs: &CRS<E>,
	gamma_g2: E::G2, // this should be hash_to_point(attestation_data)
	m: &[u8],
) -> Result<Ciphertext<E>, crate::error::Error> {
	// TODO: replace the rng
	let mut rng = ark_std::test_rng();

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
	let mut enc_key_bytes = Vec::new();
	// how do we test this line?! also will thiserror still take care of it?
	enc_key.serialize_compressed(&mut enc_key_bytes)?;
	// derive an encapsulation key from enc_key using an HKDF
	let hk = Hkdf::<Sha256>::new(None, &enc_key_bytes);
	let mut aes_key = [0u8; 32];
	let mut aes_nonce = [0u8; 12];
	// TODO: how to test?
	hk.expand(&[1], &mut aes_key)?;
	hk.expand(&[2], &mut aes_nonce)?;

	// // on failure, zero keys
	// if masked.clone().failed() {
	// 	enc_key_bytes.iter_mut().for_each(|b| *b = 0);
	// 	aes_nonce.iter_mut().for_each(|b| *b = 0);
	// }
	// encrypt the message m using the derived key
	// Q: we could make this more dynamic ala my tlock lib
	let aes_key: &Key<Aes256Gcm> = &aes_key.into();
	let cipher = Aes256Gcm::new(aes_key);
	let ct = cipher.encrypt(&aes_nonce.into(), m).map_err(|_| Error::EncryptionError)?;

	Ok(Ciphertext { gamma_g2, sa1, sa2, ct, t })
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

	type E = ark_bls12_381::Bls12_381;
	type G1 = <E as Pairing>::G1;
	type G2 = <E as Pairing>::G2;

	const MSG: &[u8] = b"Hello, world!";

	#[test]
	fn test_encryption() {
		let mut rng = ark_std::test_rng();
		let n = 8;
		let crs = CRS::new(n, &mut rng).unwrap();

		let mut sk: Vec<SecretKey<E>> = Vec::new();
		let mut pk: Vec<LagPublicKey<E>> = Vec::new();

		for i in 0..n {
			sk.push(SecretKey::<E>::new(&mut rng, i));
			pk.push(sk[i].get_lagrange_pk(i, &crs))
		}

		let (_ak, ek) = AggregateKey::<E>::new(pk, &crs);

		let gamma_g2 = G2::rand(&mut rng);

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
	fn test_encryption_with_false_mask_fails_with_encryption_error() {
		let mut rng = ark_std::test_rng();
		let n = 8;
		let crs = CRS::new(n, &mut rng).unwrap();

		let mut sk: Vec<SecretKey<E>> = Vec::new();
		let mut pk: Vec<LagPublicKey<E>> = Vec::new();

		for i in 0..n {
			sk.push(SecretKey::<E>::new(&mut rng, i));
			pk.push(sk[i].get_lagrange_pk(i, &crs))
		}

		let (_ak, ek) = AggregateKey::<E>::new(pk, &crs);

		let gamma_g2 = G2::rand(&mut rng);

		let res = encrypt::<E>(&ek, 2, &crs, gamma_g2, MSG);
		assert!(matches!(res, Err(Error::EncryptionError)));
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

		let (_ak, ek) = AggregateKey::<E>::new(pk, &crs);
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

		let (_ak, ek) = AggregateKey::<E>::new(pk, &crs);

		let gamma_g2 = G2::rand(&mut rng);

		let res = encrypt::<E>(&ek, 22, &crs, gamma_g2, MSG);
		assert!(matches!(res, Err(Error::InvalidCRS)));
	}
}
