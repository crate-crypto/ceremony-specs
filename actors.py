from dataclasses import dataclass
from email.errors import ObsoleteHeaderDefect
from typing import List, Optional
from keypair import KeyPair
from srs import SRS, SRSParameters
from srs_updates import UpdateProof

# TODO: We only create these classes so that users can see the workflow.
# Its possible to get rid of them

# The Contributor/Participant has two roles:
# - Update the SRS they have received.
# - Check that the SRS they have received is _correct_


@dataclass
class Contributor:
    keypair: KeyPair
    srs: SRS
    old_srs: Optional[SRS]

    def __init__(self, keypair: KeyPair, parameters: SRSParameters, serialised_srs: bytes):
        self.srs = SRS.from_bytes(parameters, serialised_srs)
        # Copy the old SRS because when we update the SRS, it overwrites it
        # We check the SRS after updating
        self.old_srs = self.srs.copy()
        self.keypair = keypair

    def update(self):
        return self.srs.update(self.keypair)

    def check_srs_is_correct(self):
        return self.old_srs.is_correct()

    def serialise_srs(self):
        self.srs.to_bytes()


@dataclass
class Coordinator:
    # The co-ordinator only needs to save the current SRS
    # When a new SRS has been received, they will check it against the current
    # and then replace the current_SRS if the new SRS is valid
    current_SRS: SRS
    update_proofs: List[UpdateProof] = []

    # TODO: should we allow a contributor to send multiple update proofs?
    def replace_current_srs(self, received_srs: SRS, update_proof: UpdateProof):

        if SRS.verify_updates(self.current_SRS, received_srs, [update_proof]) == False:
            return None

        self.update_proofs.append(update_proof)
        self.current_SRS = received_srs
