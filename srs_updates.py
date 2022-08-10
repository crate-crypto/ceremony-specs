from __future__ import annotations

from dataclasses import dataclass
from typing import List

from bls import G1Point, PublicKey
from product_decomposition import ProductDecompositionProof


@dataclass
class UpdateProof:
    # This is the public key associated with the
    # private key that made the update
    public_key: PublicKey
    # This is the degree-1 element of the SRS
    # after the update was made
    after_degree_1_point: G1Point

    # Verifies that a chain of update proofs are linked
    # using the product decomposition proof module
    def verify_chain(starting_point: G1Point, proofs: List[UpdateProof]):
        assert(len(proofs) > 0)

        product_proof = ProductDecompositionProof(starting_point)

        for proof in proofs:
            product_proof.extend(proof.after_degree_1_point,
                                 proof.public_key.point)

        return product_proof.verify()


UpdateProofs = List[UpdateProof]
