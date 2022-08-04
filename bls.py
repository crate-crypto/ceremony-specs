# This import is used so that we can use a type that has
# been declared later on in the python file
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple, Union
from py_ecc.optimized_bls12_381 import (
    G1 as G1Generator, G2 as G2Generator, FQ, FQ2, curve_order, multiply, is_inf, is_on_curve, optimized_pairing)
from py_ecc.bls.g2_primatives import (G1_to_pubkey as compressed_g1_to_bytes,
                                      pubkey_to_G1 as compressed_bytes_to_g1, G2_to_signature as compressed_g2_to_bytes, signature_to_G2 as compressed_bytes_to_g2)

# Types are aliased and specialised from py_ecc
# so that the methods work as expected
# `Point2D` does not seem to be exposed in the public public API.
# None signifies the identity point
G1Point = Optional[Tuple[FQ, FQ, FQ]]
G2Point = Optional[Tuple[FQ2, FQ2, FQ2]]

G1Generator = G1Generator
G2Generator = G2Generator

# When we serialise a G1 or G2 points, these constants represent
# their serialised size
#
# These will change in the future.
# We want to serialise the points in their uncompressed form
SERIALISED_G1_BYTES_SIZE = 48
SERIALISED_G2_BYTES_SIZE = 96


def is_identity(point: G1Point) -> bool:
    return is_inf(point)


def pairing(g1: G1Point, g2: G2Point):
    return optimized_pairing.pairing(g2, g1)


def is_in_group(point: Union[G1Point, G2Point]):
    return is_on_curve(point)


# slow way to check if a point is in the subgroup
def is_in_subgroup(point: Union[G1Point, G2Point]):
    return is_identity(multiply(point, curve_order))


def multiply_g1(point: G1Point, private_key: PrivateKey):
    return multiply(point, private_key.scalar)


def multiply_g2(point: G2Point, private_key: PrivateKey):
    return multiply(point, private_key.scalar)


def uncompressed_g1_to_bytes(point: G1Point):
    # TODO: py_ecc does not have the uncompressed serialisation versions
    # So for now, we use the compressed version
    byts = compressed_g1_to_bytes(point)

    assert len(byts) == SERIALISED_G1_BYTES_SIZE

    return byts


def uncompressed_bytes_to_g1(byts: bytes):
    # TODO: py_ecc does not have the uncompressed serialisation versions
    # So for now, we use the compressed version
    #
    # This method is also doing a subgroup check.
    # We do not want this here, one reason being that its done naively and is therefore slow
    # The other is that we want to optimistically contribute and then verify check after
    return compressed_bytes_to_g1(byts)


def uncompressed_g2_to_bytes(point: G2Point):
    # TODO: See comment in `uncompressed_g1_to_bytes`

    byts = compressed_g2_to_bytes(point)

    assert len(byts) == SERIALISED_G2_BYTES_SIZE

    return byts


def uncompressed_bytes_to_g2(byts: bytes):
    # TODO: See comment in `uncompressed_bytes_to_g1`
    return compressed_bytes_to_g2(byts)


@ dataclass
class PrivateKey:
    scalar: int

    def __init__(self, integer: int):
        # For python, its not certain that the integer will be reduced modulo the order
        # If you are using an implementation in Rust, you will most likely have this guarantee
        # in the form of a FieldElement data structure
        self.scalar = integer % curve_order

    def to_public_key(self) -> PublicKey:
        return PublicKey(multiply_g2(G2Generator, self))

    # Raises the private key to the power of i mod the curve order
    # This function returns a new PrivateKey leaving `self` untouched
    def pow_i(self, i: int):
        # Edge case since 0^0 is undefined
        # Note: implementations can define this to be 1 or 0
        # Either way, we are going to reject any contributions made with
        # the private key of 0
        if self.scalar == 0:
            return PrivateKey(0)
        return PrivateKey(pow(self.scalar, i, curve_order))


@ dataclass
class PublicKey:
    point: G2Point

    # Serialises the public key in compressed form
    # Its possible that we could also send this in uncompressed form.
    # Decompressing the public key is not performance critical which is
    # why compressed form was chosen. For code uniformity, we can use uncompressed form
    def to_bytes(self) -> bytes:
        return compressed_g2_to_bytes(self.point)

# from abc import ABC, abstractmethod
        # class PairingGroup(ABC):
        #     @abstractmethod
        #     def scalar_multiply(self, n, element):
        #         """
        #         Adds a group element to itself `n` times

        #         Args:
        #             n (Field): A field element
        #             rhs (Group): A group element
        #         """
        #         pass

        #     @abstractmethod
        #     def pairing(self, lhs, rhs):
        #         """
        #         Returns the pairing of two elements
        #         Args:
        #             lhs (G1point): A group element
        #             rhs (G2Point): A group element
        #         """
        #         pass

        #     @abstractmethod
        #     def identity(self):
        #         """
        #         Returns the identity for the group
        #         """
        #         pass

        #     # @abstractmethod
        #     # def order(self):
        #     #     """
        #     #     Returns the order of the group
        #     #     """
        #     #     pass

        #     @abstractmethod
        #     def generator(self):
        #         """
        #         Returns a generator for the largest prime subgroup of the group
        #         """
        #         pass

        #     @abstractmethod
        #     def serialise(self):
        #         """
        #         Returns a byte string encoding of the group
        #         """
        #         pass

        #     @abstractmethod
        #     def deserialise(self):
        #         """
        #         Returns a byte string encoding of the group
        #         """
        #         pass

        #     @abstractmethod
        #     def in_group(self):
        #         """
        #         Returns true if the element is in the group
        #         """
        #         pass
