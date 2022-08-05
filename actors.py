from dataclasses import dataclass
from typing import List, Optional
from bls import PublicKey, g2_eq
from keypair import KeyPair
from srs import SERIALISED_SRS, SRS, SRSParameters
from srs_updates import UpdateProof, UpdateProofs


# The Contributor/Participant has two roles:
# - Update the SRS they have received.
# - Check that the SRS they have received is _correct_
@dataclass
class Contributor:
    keypair: KeyPair
    srs: SRS
    # The contributor keeps two SRS's in memory because they will
    # do the subgroup checks on the SRS they received from the co-ordinator
    # _after_ they have added their contribution.
    old_srs: Optional[SRS]

    def __init__(self, keypair: KeyPair, parameters: SRSParameters, serialised_srs: SERIALISED_SRS):
        self.srs = SRS.deserialise(parameters, serialised_srs)
        # Copy the old SRS because when we update the SRS, it overwrites it
        # We check the SRS after updating
        self.old_srs = self.srs.copy()
        self.keypair = keypair

    def update_srs(self):
        return self.srs.update(self.keypair)

    # Contributors do not check that the SRS is correctly formed
    # They only do subgroup checks
    def all_elements_in_correct_subgroup(self):
        return self.old_srs.subgroup_checks()

    def serialise_srs(self):
        return self.srs.serialise()


@dataclass
class Coordinator:
    # The co-ordinator only needs to save the current SRS
    # When a new SRS has been received, they will check it against the current
    # and then replace the current_SRS if the new SRS is valid
    current_SRS: SRS
    update_proofs: List[UpdateProof]

    def __init__(self, srs: SRS):
        self.current_SRS = srs
        self.update_proofs = []

    # Note: we don't need to return boolean indicating whether the coordinator accepted
    # the contributors contribution. The coordinator will simply move onto the next person in the queue
    def replace_current_srs(self, serialised_srs: SERIALISED_SRS, update_proof: UpdateProof):

        parameters = SRSParameters(
            self.current_SRS.num_g1_points, self.current_SRS.num_g2_points)

        received_srs = SRS.deserialise(parameters, serialised_srs)
        if SRS.verify_updates(self.current_SRS, received_srs, [update_proof]) == False:
            return False
        self.update_proofs.append(update_proof)
        self.current_SRS = received_srs

        return True

    def serialise_srs(self):
        return self.current_SRS.serialise()


# A verifier has two roles,
# - To verify that the ending SRS was correctly formed from the starting SRS
# - Optionally, check that a contribution was included
@dataclass
class Verifier:
    # The SRS that the ceremony started with
    starting_srs: SRS
    # The SRS that the ceremony ended with
    ending_srs: SRS
    # The list of contribution proofs that transitioned the `starting_srs`
    # to the `ending_srs`
    update_proofs: UpdateProofs

    def __init__(self, param: SRSParameters, starting_srs: SERIALISED_SRS, ending_srs: SERIALISED_SRS, proofs: UpdateProofs):

        self.starting_srs = SRS.deserialise(param, starting_srs)
        self.ending_srs = SRS.deserialise(param, ending_srs)
        self.update_proofs = proofs

    def verify_ceremony(self):
        return SRS.verify_updates(self.starting_srs, self.ending_srs, self.update_proofs)

    # If the contributor was found, then we return their position
    # in the ceremony
    # We return None, if the contributor was not found or
    # if the ceremony was not valid
    def find_contribution(self, key: PublicKey) -> Optional[int]:
        if self.verify_ceremony() == False:
            return None
        return self.__find_contribution_no_verify(key)

    def __find_contribution_no_verify(self, key: PublicKey) -> Optional[int]:
        # Find the matching public key in the list of update proofs
        num_updates = len(self.update_proofs)
        for i in range(num_updates):
            proof = self.update_proofs[i]
            if g2_eq(key, proof.public_key):
                return i
        return None
