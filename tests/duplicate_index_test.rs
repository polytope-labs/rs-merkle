use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof, MerkleTree};

#[test]
fn duplicate_indices_should_not_verify() {
    let leaves: Vec<[u8; 32]> = ["a", "b", "c", "d"]
        .iter()
        .map(|x| Sha256::hash(x.as_bytes()))
        .collect();

    let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let root = tree.root().unwrap();

    // Legitimate single-leaf proof for index 0
    let proof = tree.proof(&[0]);
    assert!(proof.verify(root, &[0], &[leaves[0]], leaves.len()));

    // Duplicate index: same leaf claimed twice must be rejected
    assert!(!proof.verify(root, &[0, 0], &[leaves[0], leaves[0]], leaves.len()));

    // Duplicate index with a fake leaf smuggled after the real one.
    // Before the fix, the real leaf's hash was used (stable sort) and the
    // fake was silently ignored, causing verify() to return true.
    let fake = Sha256::hash(b"FAKE");
    let proof_01 = tree.proof(&[0, 1]);
    assert!(proof_01.verify(root, &[0, 1], &[leaves[0], leaves[1]], leaves.len()));
    assert!(!proof_01.verify(root, &[0, 1, 1], &[leaves[0], leaves[1], fake], leaves.len()));
}

#[test]
fn out_of_bounds_indices_should_not_verify() {
    let leaves: Vec<[u8; 32]> = ["a", "b", "c", "d"]
        .iter()
        .map(|x| Sha256::hash(x.as_bytes()))
        .collect();

    let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let root = tree.root().unwrap();
    let proof = tree.proof(&[0]);

    let fake = Sha256::hash(b"FAKE");

    // Index equal to total_leaves_count is out of bounds
    assert!(!proof.verify(root, &[4], &[fake], leaves.len()));

    // Large out-of-bounds index
    assert!(!proof.verify(root, &[100], &[fake], leaves.len()));

    // Proof extraction for valid index should still work
    assert!(proof.verify(root, &[0], &[leaves[0]], leaves.len()));
}

#[test]
fn root_returns_error_on_duplicate_indices() {
    let leaves: Vec<[u8; 32]> = ["a", "b", "c"]
        .iter()
        .map(|x| Sha256::hash(x.as_bytes()))
        .collect();

    let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let proof = tree.proof(&[0, 1]);

    let result = proof.root(&[0, 0], &[leaves[0], leaves[0]], leaves.len());
    assert!(result.is_err());
}

#[test]
fn root_returns_error_on_out_of_bounds() {
    let leaves: Vec<[u8; 32]> = ["a", "b", "c"]
        .iter()
        .map(|x| Sha256::hash(x.as_bytes()))
        .collect();

    let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let proof = tree.proof(&[0]);
    let fake = Sha256::hash(b"FAKE");

    let result = proof.root(&[3], &[fake], leaves.len());
    assert!(result.is_err());
}
