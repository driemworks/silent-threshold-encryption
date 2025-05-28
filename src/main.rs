// type E = ark_bls12_381::Bls12_381;
// type F = ark_bls12_381::Fr;

// use silent_threshold_encryption::{
//     aggregate::SystemPublicKeys,
//     crs::CRS,
//     setup::{LagPolys, SecretKey},
// };

// pub fn main() {
//     let n = 1 << 7;
//     let m = 1 << 12;
//     println!("Setting up CRS");
//     let crs = CRS::<E>::new(n, &mut ark_std::test_rng());
//     let lag_polys = LagPolys::<F>::new(n);

//     use rayon::prelude::*;

//     println!("Setting up keys");
//     let (_sk, pk): (Vec<_>, Vec<_>) = (0..m)
//         .into_par_iter()
//         .map(|i| {
//             println!("Processing key pair {}/{}", i + 1, m);
//             let sk = SecretKey::<E>::new(&mut ark_std::test_rng(), i);
//             let pk = sk.get_pk(&crs);
//             (sk, pk)
//         })
//         .unzip();

//     println!("Setting up system public keys");
//     let _system_keys = SystemPublicKeys::<E>::new(pk.clone(), &crs, &lag_polys, 3);
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
use rand::seq::IteratorRandom;

fn main() {
    let mut rng = ark_std::test_rng();
    let n = 2;
    let m = 6;
    let t: usize = 1;
    let k = 3;
    let crs = CRS::new(n, &mut rng);
    let lag_polys = LagPolys::new(n);

    let sk = (0..m)
        .map(|i| SecretKey::<E>::new(&mut rng, i))
        .collect::<Vec<_>>();
    let pk = sk.iter().map(|sk| sk.get_pk(&crs)).collect::<Vec<_>>();

    let system_keys = SystemPublicKeys::<E>::new(pk.clone(), &crs, &lag_polys, k);
}
