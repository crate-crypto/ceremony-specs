from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple
from copy import deepcopy

from bls import (G1Point, G2Point, g1_eq, g1_to_hex_str, g2_to_hex_str, gt_eq, hex_str_to_g1, hex_str_to_g2, is_identity, is_in_g1, is_in_g2, is_in_subgroup,  multiply_g1, multiply_g2, pairing,
                 G1Generator, G2Generator)
from common import pairwise, hex_str
from keypair import KeyPair
from srs_updates import UpdateProof, UpdateProofs


G1Powers = List[hex_str]
G2Powers = List[hex_str]


@dataclass
class SerialisedSRS:
    num_g1_points: int
    num_g2_points: int

    g1_points: G1Powers
    g2_points: G2Powers


@dataclass
class SRSParameters:

    num_g1_points_needed: int
    num_g2_points_needed: int

    # When the ceremony is started, we can choose to use the g1 and g2 points from
    # a separate ceremony or we can choose to start from a default ceremony.
    # We have chosen to start from a default ceremony, because we have the additional
    # requirement of needing four distinct ceremonies and for each ceremony to be
    # an exact size. Previous ceremonies were made for zkSnarks which require very large SRS's
    # and so none will satisfy the "exact size" requirement. This ultimately means that
    # those previous ceremonies will not bring any additional security.
    #
    # Elaborating further, If by chance there were four ceremonies made in the past, with
    # the same SRS sizes that we require, then it would be beneficial for us to use them.
    starting_g1: G1Point = G1Generator
    starting_g2: G2Point = G2Generator


# The SRS also known as an accumulator, is that gets passed and modified between each participant
# We serialise it in compressed form because we care more about the size of the file,
# than the time to decompress the compressed form.
@dataclass
class SRS:
    g1_points: List[G1Point]
    g2_points: List[G2Point]

    def __init__(self, param: SRSParameters, _g1_points=None, _g2_points=None):
        if _g1_points is None:
            # Use the parameters to initialise the srs
            assert _g2_points is None
            # g1_points becomes a list of size `num_g1_points_needed` where each element
            # is the same `starting_g1`
            self.g1_points = [param.starting_g1] * param.num_g1_points_needed
            self.g2_points = [param.starting_g2] * param.num_g2_points_needed
        else:
            assert len(_g1_points) == param.num_g1_points_needed
            assert len(_g2_points) == param.num_g2_points_needed

            # Initialise the SRS from the provided g1 ad g2 points
            self.g1_points = _g1_points
            self.g2_points = _g2_points

    def num_g1_points(self):
        return len(self.g1_points)

    def num_g2_points(self):
        return len(self.g2_points)

    # Update the SRS using a private key and produce an update proof
    def update(self, keypair: KeyPair):
        num_g1_points = len(self.g1_points)
        num_g2_points = len(self.g2_points)

        private_key = keypair.private_key

        for i in range(num_g1_points):
            priv_key_i = private_key.pow_i(i)
            self.g1_points[i] = multiply_g1(self.g1_points[i], priv_key_i)

        for i in range(num_g2_points):
            priv_key_i = private_key.pow_i(i)
            self.g2_points[i] = multiply_g2(self.g2_points[i], priv_key_i)

        after_degree_1_point = self.__degree_1_g1()

        return UpdateProof(keypair.public_key, after_degree_1_point)

    # Returns the G1 degree 0 element of the SRS
    def __degree_0_g1(self):
        return deepcopy(self.g1_points[0])

    # Returns the G1 degree 1 element of the SRS
    def __degree_1_g1(self):
        return deepcopy(self.g1_points[1])

    # Returns the G2 degree 0 element of the SRS
    def __degree_0_g2(self):
        return deepcopy(self.g2_points[0])

    # Returns the G2 degree 1 element of the SRS
    def __degree_1_g2(self):
        return deepcopy(self.g2_points[1])

    def copy(self):
        return deepcopy(self)

    def __from_hex_strings(param: SRSParameters, serialised_srs: Tuple[G1Powers, G2Powers]) -> SRS:
        g1_points = []
        g2_points = []

        g1_powers, g2_powers = serialised_srs

        for i in range(param.num_g1_points_needed):
            point = hex_str_to_g1(g1_powers[i])
            g1_points.append(point)

        for i in range(param.num_g2_points_needed):
            point = hex_str_to_g2(g2_powers[i])
            g2_points.append(point)

        # Check that we were given the exact amount of powers needed
        # This is placed to catch bugs, where the serialised_srs
        # is unknowingly larger than the parameters needed.
        assert len(g1_powers) == len(g1_points)
        assert len(g2_powers) == len(g2_points)

        return SRS(param, g1_points, g2_points)

    def __to_hex_strings(self) -> Tuple[G1Powers, G2Powers]:
        g1_powers = []
        g2_powers = []

        for point in self.g1_points:
            g1_powers.append(g1_to_hex_str(point))
        for point in self.g2_points:
            g2_powers.append(g2_to_hex_str(point))

        return [g1_powers, g2_powers]

    def serialise(self) -> SerialisedSRS:
        num_g1_points = self.num_g1_points()
        num_g2_points = self.num_g2_points()
        g1_powers, g2_powers = self.__to_hex_strings()

        return SerialisedSRS(num_g1_points, num_g2_points, g1_powers, g2_powers)

    def deserialise(param: SRSParameters, serialised_srs: SerialisedSRS):
        if param.num_g1_points_needed != serialised_srs.num_g1_points:
            return None
        if param.num_g2_points_needed != serialised_srs.num_g2_points:
            return None
        powers = [serialised_srs.g1_points, serialised_srs.g2_points]
        return SRS.__from_hex_strings(param, powers)

    # Check if the SRS passes our correctness checks:
    # - The first element should not be the identity point
    # - The elements in the SRS should not have a low order component
    # - Each subsequent element is a power larger than the previous.
    def is_correct(self) -> bool:
        # 1) Check that the degree-0 elements are not the identity point
        if is_identity(self.g1_points[0]):
            return False
        if is_identity(self.g2_points[0]):
            return False

        # 2) Check that each element is in the correct subgroup
        if self.subgroup_checks() == False:
            return False

        # 3) structural check
        return self.structure_check()

    # This method is to be used after the ceremony has completed.
    # One can take the SRS that was used at the start, with the SRS
    # that we ended up with. Then using the update proofs, one can verify that
    # the transformation was indeed due to the chain of update proofs
    def verify_updates(before_srs: SRS, after_srs: SRS, update_proofs: UpdateProofs):
        # 0) Both SRS's should be the same size
        if len(before_srs.g1_points) != len(after_srs.g1_points):
            return False
        if len(before_srs.g2_points) != len(after_srs.g2_points):
            return False

        # 1) First lets check that the last SRS is linked with the last update proof
        last_update = update_proofs[-1]

        if g1_eq(after_srs.__degree_1_g1(), last_update.after_degree_1_point) == False:
            return False

        # 2) Check that the update proofs are correctly linked together
        if UpdateProof.verify_chain(before_srs.__degree_1_g1(), update_proofs) == False:
            return False

        # 3) Check that the final SRS is correct.
        if after_srs.is_correct() == False:
            return False

        # Note: We do not check that `before_srs` was correct
        # This is because if `before_srs` is not correctly formed.
        # Then `after_srs` will also not be correct.
        return True

    # Check that each subsequent element of the SRS increases the degree by 1
    # ie the SRS has the correct structure
    def structure_check(self):
        tau_0_g1 = self.__degree_0_g1()
        tau_1_g1 = self.__degree_1_g1()

        tau_0_g2 = self.__degree_0_g2()
        tau_1_g2 = self.__degree_1_g2()

        # G1 structure check
        power_pairs = pairwise(self.g1_points)
        for pair in power_pairs:
            tau_i = pair[0]  # tau^i
            tau_i_next = pair[1]  # tau^{i+1}

            p1 = pairing(tau_i_next, tau_0_g2)
            p2 = pairing(tau_i, tau_1_g2)

            if gt_eq(p1, p2) == False:
                return False

        # G2 structure check
        power_pairs = pairwise(self.g2_points)
        for pair in power_pairs:
            tau_i = pair[0]  # tau^i
            tau_i_next = pair[1]  # tau^{i+1}

            p1 = pairing(tau_0_g1, tau_i_next)
            p2 = pairing(tau_1_g1, tau_i)

            if gt_eq(p1, p2) == False:
                return False

        return True

    def subgroup_checks(self):
        for point in self.g1_points:
            if is_in_g1(point) == False:
                return False
            if is_in_subgroup(point) == False:
                return False
        for point in self.g2_points:
            if is_in_g2(point) == False:
                return False
            if is_in_subgroup(point) == False:
                return False

        return True
