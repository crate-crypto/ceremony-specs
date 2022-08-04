import unittest
from bls import G1Generator, G2Generator, compressed_g1_to_bytes, compressed_g2_to_bytes
from keypair import KeyPair
from srs import SRS, SRSParameters


class TestSRS(unittest.TestCase):

    def test_generator_consistency(self):
        """
            Checks that the generator is correct.
            This test is here for those who want to check that the generator
            they have chosen, is the same as the generator being used.

            Implicitly, it also tests that the serialisation strategy
            and the endianess are the same
        """
        expected_g1_gen = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        expected_g2_gen = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"

        got_g1 = compressed_g1_to_bytes(G1Generator).hex()
        got_g2 = compressed_g2_to_bytes(G2Generator).hex()

        self.assertEqual(got_g1, expected_g1_gen)
        self.assertEqual(got_g2, expected_g2_gen)


if __name__ == '__main__':
    unittest.main()
