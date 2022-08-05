from dataclasses import dataclass
from typing import List

from bls import G1Point, G2Point, gt_eq, is_identity, pairing, G2Generator
from common import pairwise


# A product decomposition proof is capable of proving that one knows the
# product decomposition for a particular number without revealing said decomposition
@dataclass
class ProductDecompositionProof:
    running_product: List[G1Point]
    witnesses: List[G2Point]

    def __init__(self, starting_point: G1Point):
        assert is_identity(starting_point) == False

        self.running_product = [starting_point]
        self.witnesses = []

    def current_product(self):
        return self.running_product[-1]

    def extend(self, product: G1Point, witness: G2Point):
        self.running_product.append(product)
        self.witnesses.append(witness)

    def verify(self) -> bool:
        acc_pairs = pairwise(self.running_product)

        for pair, witness in zip(acc_pairs, self.witnesses):
            prev_running_product = pair[0]
            next_running_product = pair[1]

            p1 = pairing(next_running_product, G2Generator)
            p2 = pairing(prev_running_product, witness)

            if gt_eq(p1, p2) == False:
                return False
        return True
