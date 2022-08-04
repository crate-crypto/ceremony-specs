import unittest
from bls import G1Generator, PrivateKey, multiply_g1, G2Generator
from product_decomposition import ProductDecompositionProof


def add_to_product(product_proof: ProductDecompositionProof, secret: PrivateKey):
    current_product = product_proof.current_product()
    new_product = multiply_g1(current_product, secret)

    witness = secret.to_public_key()
    product_proof.extend(new_product, witness.point)


class TestProductDecomp(unittest.TestCase):

    def test_simple_product_decomp(self):
        """
            Test that a simple product decomposition proof passes
        """

        secret_a = PrivateKey(123)
        secret_b = PrivateKey(456)
        secret_c = PrivateKey(789)

        starting_point = G1Generator

        product_proof = ProductDecompositionProof(starting_point)

        # Modify the final product using the secrets
        add_to_product(product_proof, secret_a)
        add_to_product(product_proof, secret_b)
        add_to_product(product_proof, secret_c)

        # We now want to verify that the final product is a decomposition of secrets that we know
        self.assertTrue(product_proof.verify())

    def test_decomp_with_zero_always_passes(self):
        """
            Test that if one of the witnesses is zero, then the other witnesses can be anything
            Note: this does not make the proof unsound. we stop this at a higher level in the protocol
        """

        secret_a = PrivateKey(0)
        secret_b = PrivateKey(456)
        secret_c = PrivateKey(789)

        starting_point = G1Generator

        product_proof = ProductDecompositionProof(starting_point)

        # Modify the final product using the secrets
        add_to_product(product_proof, secret_a)
        add_to_product(product_proof, secret_b)
        add_to_product(product_proof, secret_c)

        # Modify the witnesses showing that it doesn't matter what they are
        product_proof.witnesses[-1] = G2Generator
        product_proof.witnesses[-2] = G2Generator

        # We now want to verify that the final product is a decomposition of secrets that we know
        self.assertTrue(product_proof.verify())


if __name__ == '__main__':
    unittest.main()
