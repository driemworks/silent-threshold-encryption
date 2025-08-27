// type E = ark_bls12_381::Bls12_381;
// type F = ark_bls12_381::Fr;

// use ark_std::{end_timer, start_timer};
// use silent_threshold_encryption::{
// 	aggregate::SystemPublicKeys,
// 	crs::CRS,
// 	setup::{LagPolys, SecretKey},
// };

// pub fn main() {
// 	let n = 1 << 7;
// 	let m = 1 << 12;
// 	println!("Setting up CRS");
// 	let crs = CRS::<E>::new(n, &mut ark_std::test_rng());
// 	let lag_polys = LagPolys::<F>::new(n);

// 	use rayon::prelude::*;

// 	println!("Setting up keys");
// 	let (_sk, pk): (Vec<_>, Vec<_>) = (0..m)
// 		.into_par_iter()
// 		.map(|i| {
// 			println!("Processing key pair {}/{}", i + 1, m);
// 			let sk = SecretKey::<E>::new(&mut ark_std::test_rng(), i);
// 			let pk = sk.get_pk(&crs);
// 			(sk, pk)
// 		})
// 		.unzip();

// 	println!("Setting up system public keys");
// 	let _system_keys = SystemPublicKeys::<E>::new(pk.clone(), &crs, &lag_polys, 3);
// }

use ark_std::{end_timer, start_timer};
use silent_threshold_encryption::{
	aggregate::SystemPublicKeys,
	crs::CRS,
	decryption::agg_dec,
	encryption::encrypt,
	setup::{LagPolys, PartialDecryption, SecretKey},
};
type E = ark_bls12_381::Bls12_381;
type G2 = <E as ark_ec::pairing::Pairing>::G2;

use ark_std::UniformRand;
use rand::seq::IteratorRandom;

use ark_serialize::CanonicalSerialize;

fn main() {
	let mut rng = ark_std::test_rng();

	let n = 2;
	let t: usize = 1;
	debug_assert!(t < n);
	let k = 1;

	let crs = CRS::new(n, &mut rng).unwrap();
	let lag_polys = LagPolys::new(n).unwrap();

	let sk = (0..n)
		.map(|i| {
			let mut rng = ark_std::test_rng();
			SecretKey::<E>::new(&mut rng, i)
		})
		.collect::<Vec<_>>();

	let pk = sk.iter().map(|sk| sk.get_pk(&crs)).collect::<Vec<_>>();

	let system_keys = SystemPublicKeys::<E>::new(pk.clone(), &crs, &lag_polys, k).unwrap();

	let mut thread_rng = rand::rng(); // Create a random number generator
								   // choose `n` random entries from [0, m]
	let subset = (0..n).choose_multiple(&mut thread_rng, n);
	let (ak, ek) = system_keys.get_aggregate_key(&subset, &crs, &lag_polys);

	let msg = b"Hello, world!";

	let mut rng = ark_std::test_rng();
	let gamma_g2 = G2::rand(&mut rng);
	let ct = encrypt::<E>(&ek, t, &crs, gamma_g2, msg).unwrap();

	// sample t random signers positions
	// let signer_positions = (0..crs.n).choose_multiple(&mut thread_rng, t);

	let signer_positions = vec![0];

	let mut selector: Vec<bool> = vec![false; n];
	selector[0] = true;
	let mut partial_decryptions: Vec<PartialDecryption<E>> = vec![PartialDecryption::zero(); n];

	for i in signer_positions {
		// selector[i] = true;
		let id = ak.lag_pks[i].id;
		partial_decryptions[i] = sk[id].partial_decryption(&ct);
	}

	let mut test0 = Vec::new();
	partial_decryptions.iter().for_each(|pd| {
		let mut test = Vec::new();
		pd.serialize_compressed(&mut test).unwrap();
		test0.push(test);
	});

	// let mut test1 = Vec::new();
	// ct.serialize_compressed(&mut test1).unwrap();
	// crs.serialize_compressed(&mut test).unwrap();
	// panic!("{:?}", test);

	// let mut test = Vec::new();
	// crs.serialize_compressed(&mut test).unwrap();
	// panic!("{:?}", test);
	// panic!("{:?}", selector);

	let dec_timer = start_timer!(|| "Aggregating partial decryptions and decrypting");

	// pd, ct
	// panic!("{:?}", test0);

	let dec_key = agg_dec(&partial_decryptions, &ct, &selector, &ak, &crs).unwrap();
	end_timer!(dec_timer);
	assert_eq!(dec_key, msg, "Decryption failed!");
	println!("Decryption successful!");
}
