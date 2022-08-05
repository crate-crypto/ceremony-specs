from dataclasses import dataclass
from typing import List, Tuple
from actors import Contributor
from keypair import KeyPair
from srs import SRS, G1Powers, G2Powers, SRSParameters
from srs_updates import UpdateProof, UpdateProofs
from common import hex_str


# We are running four small ceremonies each of a different size
NUM_OF_CEREMONIES = 4

# Constants represent the number of G1 powers
# needed for each ceremony
CEREMONY_1_NUM_G1_POWERS = 4096  # 2^12
CEREMONY_2_NUM_G1_POWERS = 8192  # 2^13
CEREMONY_3_NUM_G1_POWERS = 16384  # 2^14
CEREMONY_4_NUM_G1_POWERS = 32768  # 2^15

# All ceremonies require the same number of G2 points
CEREMONY_NUM_G2_POWERS = 65

NUM_G1_POWERS_NEEDED = [CEREMONY_1_NUM_G1_POWERS, CEREMONY_2_NUM_G1_POWERS,
                        CEREMONY_3_NUM_G1_POWERS, CEREMONY_4_NUM_G1_POWERS]


@dataclass
class Ceremony:
    num_g1_powers: int
    num_g2_powers: int
    powers_of_tau: Tuple[G1Powers, G2Powers]


@dataclass
class Transcript:
    # We are running four small ceremonies in one.
    # Python does not have typing like [Ceremony; 4]
    # So we use a tuple with four elements. We could use
    # Annotated[List[Ceremony], 4] , but since the number of ceremonies
    # will not change, this type hint coupled with said comment
    # is sufficient.
    # The Ceremonies are assumed to be order in ascending order
    # If this is not the case, when we check the NUM_G1_POWERS
    # It will fail
    sub_ceremonies: Tuple[Ceremony, Ceremony, Ceremony, Ceremony]


# Since we changed the specs, the transcript does not contain the update proofs, so we return it when we
# update the transcript
def update_transcript(transcript: Transcript, secrets: List[hex_str]) -> Tuple[Transcript, UpdateProofs]:
    assert len(secrets) == NUM_OF_CEREMONIES

    # Create a KeyPair for each ceremony using the provided secrets/randomness
    keypairs: List[KeyPair] = []
    for secret in secrets:

        keypair = KeyPair(secret)
        keypairs.append(keypair)

    # Emulate four Contributors, one for each ceremony
    contributors: List[Contributor] = []
    for (keypair, ceremony, num_g1_powers) in zip(keypairs, transcript.sub_ceremonies, NUM_G1_POWERS_NEEDED):

        assert ceremony.num_g1_powers == num_g1_powers
        assert ceremony.num_g2_powers == CEREMONY_NUM_G2_POWERS

        params = SRSParameters(ceremony.num_g1_powers, ceremony.num_g2_powers)

        contributor = Contributor(keypair, params, ceremony.powers_of_tau)
        contributors.append(contributor)

    # Update SRS's with contribution and return the update proofs
    update_proofs: List[UpdateProof] = []
    for contributor in contributors:
        proof = contributor.update_srs()
        update_proofs.append(proof)

    # # Perform checks -- Since we are using optimistic contribution.
    # # The checks that the contributor needs to do are done after they have sent the
    # # srs to the coordinator
    # for contributor in contributors:
    #     if contributor.all_elements_in_correct_subgroup() == False:
    #         return None

    return (transcript, update_proofs)


def transcript_subgroup_check(transcript: Transcript) -> bool:
    for ceremony in transcript.sub_ceremonies:

        params = SRSParameters(ceremony.num_g1_powers, ceremony.num_g2_powers)
        srs = SRS.deserialise(params, ceremony.powers_of_tau)
        if srs.subgroup_checks() == False:
            return False

    return True
