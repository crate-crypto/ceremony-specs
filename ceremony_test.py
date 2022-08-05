import random
import unittest
from keypair import KeyPair
from actors import Coordinator, Contributor, Verifier, SRSParameters
from srs import SERIALISED_SRS, SRS


def new_contributor(params: SRSParameters, serialised_srs: SERIALISED_SRS) -> Contributor:
    # Generate 64 random bytes.
    # Do not use this function in production.
    byts = random.randbytes(64)
    keypair = KeyPair(byts.hex())

    return Contributor(keypair, params, serialised_srs)


class TestSimpleCeremony(unittest.TestCase):

    def test_ceremony(self):
        """
            Test a small ceremony setup
        """

        NUM_CONTRIBUTORS = 3

        # STAGE 0 : Setup the parameters for the ceremony and the starting SRS
        num_g1_points_needed = 5
        num_g2_points_needed = 2
        parameters = SRSParameters(num_g1_points_needed, num_g2_points_needed)
        starting_srs = SRS(parameters)

        # STAGE 1: Setup the co-ordinator
        coordinator = Coordinator(starting_srs)
        starting_srs_serialised = coordinator.serialise_srs()

        # STAGE 2: Run the Ceremony. The coordinator communicates back and forth with
        # contributors
        pub_keys = []
        for _ in range(NUM_CONTRIBUTORS):
            # Contributor receives SRS from coordinator
            serialised_srs = coordinator.serialise_srs()
            contributor = new_contributor(parameters, serialised_srs)

            pub_keys.append(contributor.keypair.public_key)

            # Contributor adds their randomness into the SRS and
            # sends it back to the coordinator
            proof = contributor.update_srs()
            serialised_srs_updated = contributor.serialise_srs()

            self.assertEqual(proof.after_degree_1_point,
                             contributor.srs.degree_1_g1())

            # Coordinator checks the SRS received. Replaces their old SRS
            # with the one received from the coordinator, if it passes
            # the necessary checks. The proof is also saved
            self.assertTrue(coordinator.replace_current_srs(
                serialised_srs_updated, proof))

            # The contributor does their subgroup checks on the SRS they originally received from
            # the Coordinator
            # Its commented out because its really slow
            # if contributor.all_elements_in_correct_subgroup() == False:
            #     print("Contributor does not attest to participating, since some points had low order")

        ending_srs_serialised = coordinator.serialise_srs()
        proofs = coordinator.update_proofs

        # STAGE 3: Once the ceremony has finished. Once can verify that it was carried out correctly.
        verifier = Verifier(parameters, starting_srs_serialised,
                            ending_srs_serialised, proofs)
        self.assertTrue(verifier.verify_ceremony())

        # One can also find which position they were in the ceremony
        for contributor_index in range(NUM_CONTRIBUTORS):
            got_index = verifier.find_contribution_no_verify(
                pub_keys[contributor_index])
            self.assertEqual(got_index, contributor_index)

        # If a contributor did not contribute during the ceremony,
        # Then this function returns None
        unknown_contributor = new_contributor(
            parameters, ending_srs_serialised)
        contributor_index = verifier.find_contribution_no_verify(
            unknown_contributor.keypair.public_key)
        self.assertIsNone(contributor_index)


if __name__ == '__main__':
    unittest.main()
