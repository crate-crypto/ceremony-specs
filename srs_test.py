import unittest
from bls import is_identity, compressed_g1_to_bytes, compressed_g2_to_bytes
from keypair import KeyPair
from srs import SRS, SRSParameters


class TestSRS(unittest.TestCase):

    def test_no_update__allowed(self):
        """
            Checks that if the user makes their private key `1`
            Then it is the same as no update.
            We note that this is allowed in the ceremony and should be accepted.
        """
        # Since the secret is 1, the SRS should not change
        secret = 1
        keys = KeyPair(secret)

        # Size of the setup
        num_g1_elements_needed = 3
        num_g2_elements_needed = 2

        params = SRSParameters(num_g1_elements_needed, num_g2_elements_needed)

        srs = SRS(params)

        update_proof = srs.update(keys)

        self.assertEqual(update_proof.before_degree_1_point,
                         update_proof.after_degree_1_point)

    def test_zero_update__not_allowed(self):
        """
            Checks that if the user makes their private key `0`
            Then the resultant SRS is a list of the identity point
            We note that this is NOT allowed in the ceremony and should not be accepted.
        """
        secret = 0
        keys = KeyPair(secret)

        # Size of the setup
        num_g1_elements_needed = 3
        num_g2_elements_needed = 2

        params = SRSParameters(num_g1_elements_needed, num_g2_elements_needed)

        srs = SRS(params)

        srs.update(keys)

        for point in srs.g1_points:
            self.assertTrue(is_identity(point))
        for point in srs.g2_points:
            self.assertTrue(is_identity(point))

        self.assertFalse(srs.is_correct())

    def test_serialisation_consistency(self):
        """
            Checks that when we serialise/deserialise are consistent
        """
        # Size of the setup
        num_g1_elements_needed = 3
        num_g2_elements_needed = 2

        params = SRSParameters(num_g1_elements_needed, num_g2_elements_needed)

        srs = SRS(params)

        srs.update(KeyPair(2))

        serialised_srs = srs.serialise()
        deserialised_srs = SRS.deserialise(params, serialised_srs)

        # Check that the sizes are the same
        self.assertEqual(len(srs.g1_points), len(deserialised_srs.g1_points))
        self.assertEqual(len(srs.g2_points), len(deserialised_srs.g2_points))

        for point, des_point in zip(srs.g1_points, deserialised_srs.g1_points):
            self.assertEqual(compressed_g1_to_bytes(point),
                             compressed_g1_to_bytes(des_point))

        for point, des_point in zip(srs.g2_points, deserialised_srs.g2_points):
            self.assertEqual(compressed_g2_to_bytes(point),
                             compressed_g2_to_bytes(des_point))


if __name__ == '__main__':
    unittest.main()
