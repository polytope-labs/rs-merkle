use tiny_keccak::keccak256;
use rs_merkle::utils::indices::div_floor;

mod common;

pub fn calculate_root(proof: Vec<Vec<(usize, [u8; 32])>>) -> [u8; 32] {
    let mut previous_layer = vec![];
    for  layer in proof {
        let mut current_layer = vec![];
        if previous_layer.len() == 0 {
            current_layer = layer;
        } else {
            current_layer.extend(previous_layer.drain(..));
            current_layer.extend(&layer);
            current_layer.sort_by(|(a_i, _), (b_i, _)| a_i.cmp(b_i));
        }

        for index in (0..current_layer.len()).step_by(2) {
            if index + 1 >= current_layer.len() {
                let node = current_layer[index].clone();
                previous_layer.push((div_floor(node.0, 2), node.1));
            } else {
                let mut concat = vec![];
                let mut left = current_layer[index].clone();
                let right = current_layer[index + 1].clone();
                concat.extend(&left.1);
                concat.extend(&right.1);
                let hash = keccak256(&concat);

                previous_layer.push((div_floor(left.0, 2), hash));
            }
        }
    }

    debug_assert!(previous_layer.len(), 1);

    previous_layer[0].1
}

pub mod root {
    use tiny_keccak::keccak256;
    use crate::{calculate_root, common};
    use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};
    use rs_merkle::utils::indices::{div_ceil, div_floor, tree_depth};

    #[derive(Clone)]
    struct Keccak256;

    impl Hasher for Keccak256 {
        type Hash = [u8; 32];

        fn hash(data: &[u8]) -> [u8; 32] {
            keccak256(data)
        }
    }


    #[test]
    fn test_addresses() {
        let testAddresses = [
            "9aF1Ca5941148eB6A3e9b9C741b69738292C533f",
            "DD6ca953fddA25c496165D9040F7F77f75B75002",
            "60e9C47B64Bc1C7C906E891255EaEC19123E7F42",
            "fa4859480Aa6D899858DE54334d2911E01C070df",
            "19B9b128470584F7209eEf65B69F3624549Abe6d",
            "C436aC1f261802C4494504A11fc2926C726cB83b",
            "c304C8C2c12522F78aD1E28dD86b9947D7744bd0",
            "Da0C2Cba6e832E55dE89cF4033affc90CC147352",
            "f850Fd22c96e3501Aad4CDCBf38E4AEC95622411",
            "684918D4387CEb5E7eda969042f036E226E50642",
            "963F0A1bFbb6813C0AC88FcDe6ceB96EA634A595",
            "39B38ad74b8bCc5CE564f7a27Ac19037A95B6099",
            "C2Dec7Fdd1fef3ee95aD88EC8F3Cd5bd4065f3C7",
            "9E311f05c2b6A43C2CCF16fB2209491BaBc2ec01",
            "927607C30eCE4Ef274e250d0bf414d4a210b16f0",
            "98882bcf85E1E2DFF780D0eB360678C1cf443266",
            "FBb50191cd0662049E7C4EE32830a4Cc9B353047",
            "963854fc2C358c48C3F9F0A598B9572c581B8DEF",
            "F9D7Bc222cF6e3e07bF66711e6f409E51aB75292",
            "F2E3fd32D063F8bBAcB9e6Ea8101C2edd899AFe6",
            "407a5b9047B76E8668570120A96d580589fd1325",
            "EAD9726FAFB900A07dAd24a43AE941d2eFDD6E97",
            "42f5C8D9384034A9030313B51125C32a526b6ee8",
            "158fD2529Bc4116570Eb7C80CC76FEf33ad5eD95",
            "0A436EE2E4dEF3383Cf4546d4278326Ccc82514E",
            "34229A215db8FeaC93Caf8B5B255e3c6eA51d855",
            "Eb3B7CF8B1840242CB98A732BA464a17D00b5dDF",
            "2079692bf9ab2d6dc7D79BBDdEE71611E9aA3B72",
            "46e2A67e5d450e2Cf7317779f8274a2a630f3C9B",
            "A7Ece4A5390DAB18D08201aE18800375caD78aab",
            "15E1c0D24D62057Bf082Cb2253dA11Ef0d469570",
            "ADDEF4C9b5687Eb1F7E55F2251916200A3598878",
            "e0B16Fb96F936035db2b5A68EB37D470fED2f013",
            "0c9A84993feaa779ae21E39F9793d09e6b69B62D",
            "3bc4D5148906F70F0A7D1e2756572655fd8b7B34",
            "Ff4675C26903D5319795cbd3a44b109E7DDD9fDe",
            "Cec4450569A8945C6D2Aba0045e4339030128a92",
            "85f0584B10950E421A32F471635b424063FD8405",
            "b38bEe7Bdc0bC43c096e206EFdFEad63869929E3",
            "c9609466274Fef19D0e58E1Ee3b321D5C141067E",
            "a08EA868cF75268E7401021E9f945BAe73872ecc",
            "67C9Cb1A29E964Fe87Ff669735cf7eb87f6868fE",
            "1B6BEF636aFcdd6085cD4455BbcC93796A12F6E2",
            "46B37b243E09540b55cF91C333188e7D5FD786dD",
            "8E719E272f62Fa97da93CF9C941F5e53AA09e44a",
            "a511B7E7DB9cb24AD5c89fBb6032C7a9c2EfA0a5",
            "4D11FDcAeD335d839132AD450B02af974A3A66f8",
            "B8cf790a5090E709B4619E1F335317114294E17E",
            "7f0f57eA064A83210Cafd3a536866ffD2C5eDCB3",
            "C03C848A4521356EF800e399D889e9c2A25D1f9E",
            "C6b03DF05cb686D933DD31fCa5A993bF823dc4FE",
            "58611696b6a8102cf95A32c25612E4cEF32b910F",
            "2ed4bC7197AEF13560F6771D930Bf907772DE3CE",
            "3C5E58f334306be029B0e47e119b8977B2639eb4",
            "288646a1a4FeeC560B349d210263c609aDF649a6",
            "b4F4981E0d027Dc2B3c86afA0D0fC03d317e83C0",
            "aAE4A87F8058feDA3971f9DEd639Ec9189aA2500",
            "355069DA35E598913d8736E5B8340527099960b8",
            "3cf5A0F274cd243C0A186d9fCBdADad089821B93",
            "ca55155dCc4591538A8A0ca322a56EB0E4aD03C4",
            "E824D0268366ec5C4F23652b8eD70D552B1F2b8B",
            "84C3e9B25AE8a9b39FF5E331F9A597F2DCf27Ca9",
            "cA0018e278751De10d26539915d9c7E7503432FE",
            "f13077dE6191D6c1509ac7E088b8BE7Fe656c28b",
            "7a6bcA1ec9Db506e47ac6FD86D001c2aBc59C531",
            "eA7f9A2A9dd6Ba9bc93ca615C3Ddf26973146911",
            "8D0d8577e16F8731d4F8712BAbFa97aF4c453458",
            "B7a7855629dF104246997e9ACa0E6510df75d0ea",
            "5C1009BDC70b0C8Ab2e5a53931672ab448C17c89",
            "40B47D1AfefEF5eF41e0789F0285DE7b1C31631C",
            "5086933d549cEcEB20652CE00973703CF10Da373",
            "eb364f6FE356882F92ae9314fa96116Cf65F47d8",
            "dC4D31516A416cEf533C01a92D9a04bbdb85EE67",
            "9b36E086E5A274332AFd3D8509e12ca5F6af918d",
            "BC26394fF36e1673aE0608ce91A53B9768aD0D76",
            "81B5AB400be9e563fA476c100BE898C09966426c",
            "9d93C8ae5793054D28278A5DE6d4653EC79e90FE",
            "3B8E75804F71e121008991E3177fc942b6c28F50",
            "C6Eb5886eB43dD473f5BB4e21e56E08dA464D9B4",
            "fdf1277b71A73c813cD0e1a94B800f4B1Db66DBE",
            "c2ff2cCc98971556670e287Ff0CC39DA795231ad",
            "76b7E1473f0D0A87E9B4a14E2B179266802740f5",
            "A7Bc965660a6EF4687CCa4F69A97563163A3C2Ef",
            "B9C2b47888B9F8f7D03dC1de83F3F55E738CebD3",
            "Ed400162E6Dd6bD2271728FFb04176bF770De94a",
            "E3E8331156700339142189B6E555DCb2c0962750",
            "bf62e342Bc7706a448EdD52AE871d9C4497A53b1",
            "b9d7A1A111eed75714a0AcD2dd467E872eE6B03D",
            "03942919DFD0383b8c574AB8A701d89fd4bfA69D",
            "0Ef4C92355D3c8c7050DFeb319790EFCcBE6fe9e",
            "A6895a3cf0C60212a73B3891948ACEcF1753f25E",
            "0Ed509239DB59ef3503ded3d31013C983d52803A",
            "c4CE8abD123BfAFc4deFf37c7D11DeCd5c350EE4",
            "4A4Bf59f7038eDcd8597004f35d7Ee24a7Bdd2d3",
            "5769E8e8A2656b5ed6b6e6fa2a2bFAeaf970BB87",
            "f9E15cCE181332F4F57386687c1776b66C377060",
            "c98f8d4843D56a46C21171900d3eE538Cc74dbb5",
            "3605965B47544Ce4302b988788B8195601AE4dEd",
            "e993BDfdcAac2e65018efeE0F69A12678031c71d",
            "274fDf8801385D3FAc954BCc1446Af45f5a8304c",
            "BFb3f476fcD6429F4a475bA23cEFdDdd85c6b964",
            "806cD16588Fe812ae740e931f95A289aFb4a4B50",
            "a89488CE3bD9C25C3aF797D1bbE6CA689De79d81",
            "d412f1AfAcf0Ebf3Cd324593A231Fc74CC488B12",
            "d1f715b2D7951d54bc31210BbD41852D9BF98Ed1",
            "f65aD707c344171F467b2ADba3d14f312219cE23",
            "2971a4b242e9566dEF7bcdB7347f5E484E11919B",
            "12b113D6827E07E7D426649fBd605f427da52314",
            "1c6CA45171CDb9856A6C9Dba9c5F1216913C1e97",
            "11cC6ee1d74963Db23294FCE1E3e0A0555779CeA",
            "8Aa1C721255CDC8F895E4E4c782D86726b068667",
            "A2cDC1f37510814485129aC6310b22dF04e9Bbf0",
            "Cf531b71d388EB3f5889F1f78E0d77f6fb109767",
            "Be703e3545B2510979A0cb0C440C0Fba55c6dCB5",
            "30a35886F989db39c797D8C93880180Fdd71b0c8",
            "1071370D981F60c47A9Cd27ac0A61873a372cBB2",
            "3515d74A11e0Cb65F0F46cB70ecf91dD1712daaa",
            "50500a3c2b7b1229c6884505D00ac6Be29Aecd0C",
            "9A223c2a11D4FD3585103B21B161a2B771aDA3d1",
            "d7218df03AD0907e6c08E707B15d9BD14285e657",
            "76CfD72eF5f93D1a44aD1F80856797fBE060c70a",
            "44d093cB745944991EFF5cBa151AA6602d6f5420",
            "626516DfF43bf09A71eb6fd1510E124F96ED0Cde",
            "6530824632dfe099304E2DC5701cA99E6d031E08",
            "57e6c423d6a7607160d6379A0c335025A14DaFC0",
            "3966D4AD461Ef150E0B10163C81E79b9029E69c3",
            "F608aCfd0C286E23721a3c347b2b65039f6690F1",
            "bfB8FAac31A25646681936977837f7740fCd0072",
            "d80aa634a623a7ED1F069a1a3A28a173061705c7",
            "9122a77B36363e24e12E1E2D73F87b32926D3dF5",
            "62562f0d1cD31315bCCf176049B6279B2bfc39C2",
            "48aBF7A2a7119e5675059E27a7082ba7F38498b2",
            "b4596983AB9A9166b29517acD634415807569e5F",
            "52519D16E20BC8f5E96Da6d736963e85b2adA118",
            "7663893C3dC0850EfC5391f5E5887eD723e51B83",
            "5FF323a29bCC3B5b4B107e177EccEF4272959e61",
            "ee6e499AdDf4364D75c05D50d9344e9daA5A9AdF",
            "1631b0BD31fF904aD67dD58994C6C2051CDe4E75",
            "bc208e9723D44B9811C428f6A55722a26204eEF2",
            "e76103a222Ee2C7Cf05B580858CEe625C4dc00E1",
            "C71Bb2DBC51760f4fc2D46D84464410760971B8a",
            "B4C18811e6BFe564D69E12c224FFc57351f7a7ff",
            "D11DB0F5b41061A887cB7eE9c8711438844C298A",
            "B931269934A3D4432c084bAAc3d0de8143199F4f",
            "070037cc85C761946ec43ea2b8A2d5729908A2a1",
            "2E34aa8C95Ffdbb37f14dCfBcA69291c55Ba48DE",
            "052D93e8d9220787c31d6D83f87eC7dB088E998f",
            "498dAC6C69b8b9ad645217050054840f1D91D029",
            "E4F7D60f9d84301e1fFFd01385a585F3A11F8E89",
            "Ea637992f30eA06460732EDCBaCDa89355c2a107",
            "4960d8Da07c27CB6Be48a79B96dD70657c57a6bF",
            "7e471A003C8C9fdc8789Ded9C3dbe371d8aa0329",
            "d24265Cc10eecb9e8d355CCc0dE4b11C556E74D7",
            "DE59C8f7557Af779674f41CA2cA855d571018690",
            "2fA8A6b3b6226d8efC9d8f6EBDc73Ca33DDcA4d8",
            "e44102664c6c2024673Ff07DFe66E187Db77c65f",
            "94E3f4f90a5f7CBF2cc2623e66B8583248F01022",
            "0383EdBbc21D73DEd039E9C1Ff6bf56017b4CC40",
            "64C3E49898B88d1E0f0d02DA23E0c00A2Cd0cA99",
            "F4ccfB67b938d82B70bAb20975acFAe402E812E1",
            "4f9ee5829e9852E32E7BC154D02c91D8E203e074",
            "b006312eF9713463bB33D22De60444Ba95609f6B",
            "7Cbe76ef69B52110DDb2e3b441C04dDb11D63248",
            "70ADEEa65488F439392B869b1Df7241EF317e221",
            "64C0bf8AA36Ba590477585Bc0D2BDa7970769463",
            "A4cDc98593CE52d01Fe5Ca47CB3dA5320e0D7592",
            "c26B34D375533fFc4c5276282Fa5D660F3d8cbcB",
        ];

        let leaf_hashes = testAddresses.iter().map(|h| keccak256(&hex::decode(h).unwrap())).collect::<Vec<[u8; 32]>>();

        dbg!(tree_depth(leaf_hashes.len()));

        let tree = MerkleTree::<Keccak256>::from_leaves(&leaf_hashes);

        println!("\n\n{:?}\n\n", tree.root_hex());

        let proof = tree.proof_2d(&[0, 2, 5, 9]);
        let calculated = calculate_root(proof);

        println!("\n\n{:?}\n\n", hex::encode(&calculated));

        assert_eq!(calculated, tree.root().unwrap());

    }

    #[test]
    pub fn should_return_a_correct_root() {
        let test_data = common::setup();

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&test_data.leaf_hashes);

        assert_eq!(
            merkle_tree.root_hex(),
            Some(test_data.expected_root_hex.to_string())
        );
    }
}

pub mod tree_depth {
    use crate::common;
    use rs_merkle::{algorithms::Sha256, MerkleTree};

    #[test]
    pub fn should_return_a_correct_tree_depth() {
        let test_data = common::setup();

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&test_data.leaf_hashes);

        let depth = merkle_tree.depth();
        assert_eq!(depth, 3)
    }
}

pub mod proof {
    use crate::common;
    use rs_merkle::{algorithms::Sha256, MerkleTree};

    #[test]
    pub fn should_return_a_correct_proof() {
        let test_data = common::setup();
        let indices_to_prove = vec![3, 4];
        let expected_proof_hashes = [
            "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6",
            "252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111",
            "e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a",
        ];

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&test_data.leaf_hashes);
        let proof = merkle_tree.proof(&indices_to_prove);
        let proof_hashes = proof.proof_hashes_hex();

        assert_eq!(proof_hashes, expected_proof_hashes)
    }
}

pub mod commit {
    use crate::common;
    use rs_merkle::{algorithms::Sha256, Error, Hasher, MerkleTree};

    #[test]
    pub fn should_give_correct_root_after_commit() {
        let test_data = common::setup();
        let expected_root = test_data.expected_root_hex.clone();
        let leaf_hashes = &test_data.leaf_hashes;
        let vec = Vec::<[u8; 32]>::new();

        // Passing empty vec to create an empty tree
        let mut merkle_tree = MerkleTree::<Sha256>::from_leaves(&vec);
        let merkle_tree2 = MerkleTree::<Sha256>::from_leaves(&leaf_hashes);
        // Adding leaves
        merkle_tree.append(leaf_hashes.clone().as_mut());
        let root = merkle_tree.uncommitted_root_hex();

        assert_eq!(merkle_tree2.root_hex(), Some(expected_root.to_string()));
        assert_eq!(root, Some(expected_root.to_string()));

        let expected_root = "e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034";
        let leaf = Sha256::hash("g".as_bytes());
        merkle_tree.insert(leaf);

        assert_eq!(
            merkle_tree.uncommitted_root_hex(),
            Some(expected_root.to_string())
        );

        // No changes were committed just yet, tree is empty
        assert_eq!(merkle_tree.root(), None);

        merkle_tree.commit();

        let mut new_leaves = vec![Sha256::hash("h".as_bytes()), Sha256::hash("k".as_bytes())];
        merkle_tree.append(&mut new_leaves);

        assert_eq!(
            merkle_tree.root_hex(),
            Some("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034".to_string())
        );
        assert_eq!(
            merkle_tree.uncommitted_root_hex(),
            Some("09b6890b23e32e607f0e5f670ab224e36af8f6599cbe88b468f4b0f761802dd6".to_string())
        );

        merkle_tree.commit();
        let leaves = merkle_tree
            .leaves()
            .expect("expect the tree to have some leaves");
        let reconstructed_tree = MerkleTree::<Sha256>::from_leaves(&leaves);

        // Check that the commit is applied correctly
        assert_eq!(
            reconstructed_tree.root_hex(),
            Some("09b6890b23e32e607f0e5f670ab224e36af8f6599cbe88b468f4b0f761802dd6".to_string())
        );
    }

    #[test]
    pub fn should_not_change_the_result_when_called_twice() {
        let elements = ["a", "b", "c", "d", "e", "f"];
        let mut leaves: Vec<[u8; 32]> = elements
            .iter()
            .map(|x| Sha256::hash(x.as_bytes()))
            .collect();

        let mut merkle_tree: MerkleTree<Sha256> = MerkleTree::new();

        // Appending leaves to the tree without committing
        merkle_tree.append(&mut leaves);

        // Without committing changes we can get the root for the uncommitted data, but committed
        // tree still doesn't have any elements
        assert_eq!(merkle_tree.root(), None);
        assert_eq!(
            merkle_tree.uncommitted_root_hex(),
            Some("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2".to_string())
        );

        // Committing the changes
        merkle_tree.commit();

        // Changes applied to the tree after commit, and since there's no new staged changes
        assert_eq!(
            merkle_tree.root_hex(),
            Some("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2".to_string())
        );
        assert_eq!(merkle_tree.uncommitted_root_hex(), None);

        // Adding a new leaf
        merkle_tree.insert(Sha256::hash("g".as_bytes()));
        assert_eq!(
            merkle_tree.uncommitted_root_hex(),
            Some("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034".to_string())
        );
        merkle_tree.commit();

        // Root was updated after insertion
        assert_eq!(
            merkle_tree.root_hex(),
            Some("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034".to_string())
        );

        // Adding some more leaves
        merkle_tree
            .append(vec![Sha256::hash("h".as_bytes()), Sha256::hash("k".as_bytes())].as_mut());
        merkle_tree.commit();
        merkle_tree.commit();
        assert_eq!(
            merkle_tree.root_hex(),
            Some("09b6890b23e32e607f0e5f670ab224e36af8f6599cbe88b468f4b0f761802dd6".to_string())
        );

        // Rolling back to the previous state
        merkle_tree.rollback();
        assert_eq!(
            merkle_tree.root_hex(),
            Some("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034".to_string())
        );

        // We can rollback multiple times as well
        merkle_tree.rollback();
        assert_eq!(
            merkle_tree.root_hex(),
            Some("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2".to_string())
        );
    }
}

pub mod rollback {
    use crate::common;
    use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};

    #[test]
    pub fn should_rollback_previous_commit() {
        let leaf_values = ["a", "b", "c", "d", "e", "f"];
        let leaves: Vec<[u8; 32]> = leaf_values
            .iter()
            .map(|x| Sha256::hash(x.as_bytes()))
            .collect();

        let mut merkle_tree: MerkleTree<Sha256> = MerkleTree::new();
        merkle_tree.append(leaves.clone().as_mut());
        // No changes were committed just yet, tree is empty
        assert_eq!(merkle_tree.root(), None);

        merkle_tree.commit();

        assert_eq!(
            merkle_tree.root_hex(),
            Some("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2".to_string())
        );

        // Adding a new leaf
        merkle_tree.insert(Sha256::hash("g".as_bytes()));

        // Uncommitted root must reflect the insert
        assert_eq!(
            merkle_tree.uncommitted_root_hex(),
            Some("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034".to_string())
        );

        merkle_tree.commit();

        // After calling commit, uncommitted root will become committed
        assert_eq!(
            merkle_tree.root_hex(),
            Some("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034".to_string())
        );

        // Adding some more leaves
        merkle_tree
            .append(vec![Sha256::hash("h".as_bytes()), Sha256::hash("k".as_bytes())].as_mut());

        // Checking that the uncommitted root has changed, but the committed one hasn't
        assert_eq!(
            merkle_tree.uncommitted_root_hex(),
            Some("09b6890b23e32e607f0e5f670ab224e36af8f6599cbe88b468f4b0f761802dd6".to_string())
        );
        assert_eq!(
            merkle_tree.root_hex(),
            Some("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034".to_string())
        );

        merkle_tree.commit();

        // Checking committed changes again
        assert_eq!(
            merkle_tree.root_hex(),
            Some("09b6890b23e32e607f0e5f670ab224e36af8f6599cbe88b468f4b0f761802dd6".to_string())
        );

        merkle_tree.rollback();

        // Check that we rolled one commit back
        assert_eq!(
            merkle_tree.root_hex(),
            Some("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034".to_string())
        );

        merkle_tree.rollback();

        // Rolling back to the state after the very first commit
        assert_eq!(
            merkle_tree.root_hex(),
            Some("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2".to_string())
        );
    }
}
