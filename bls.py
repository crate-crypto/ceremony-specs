# This import is used so that we can use a type that has
# been declared later on in the python file
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple, Union
from py_ecc.optimized_bls12_381 import (
    G1 as G1Generator, G2 as G2Generator, FQ, FQ2, FQ12, curve_order, multiply, is_inf, is_on_curve, optimized_pairing, eq, b, b2)
from py_ecc.bls.g2_primatives import (G1_to_pubkey as compressed_g1_to_bytes,
                                      pubkey_to_G1 as compressed_bytes_to_g1, G2_to_signature as compressed_g2_to_bytes, signature_to_G2 as compressed_bytes_to_g2)
from common import bytes_from_hex, bytes_to_hex, hex_str

# Types are aliased and specialised from py_ecc
# so that the methods work as expected
# Need this because `Point2D` does not seem to be exposed in the public public API.
# None signifies the identity point
G1Point = Optional[Tuple[FQ, FQ, FQ]]
G2Point = Optional[Tuple[FQ2, FQ2, FQ2]]
GT = FQ12

# Re-exports
G1Generator = G1Generator
G2Generator = G2Generator
#
compressed_bytes_to_g1 = compressed_bytes_to_g1
compressed_g1_to_bytes = compressed_g1_to_bytes
compressed_bytes_to_g2 = compressed_bytes_to_g2
compressed_g2_to_bytes = compressed_g2_to_bytes


def is_identity(point: G1Point) -> bool:
    return is_inf(point)


def g1_eq(lhs: G1Point, rhs: G1Point):
    return eq(lhs, rhs)


def g2_eq(lhs: G2Point, rhs: G2Point):
    return eq(lhs, rhs)


def gt_eq(lhs: FQ12, rhs: FQ12):
    return lhs == rhs


def pairing(g1: G1Point, g2: G2Point):
    return optimized_pairing.pairing(g2, g1)


def is_in_g1(point: Union[G1Point, G2Point]):
    return is_on_curve(point, b)


def is_in_g2(point: Union[G1Point, G2Point]):
    return is_on_curve(point, b2)


# slow way to check if a point is in the subgroup
def is_in_subgroup(point: Union[G1Point, G2Point]):
    return is_identity(multiply(point, curve_order))


def multiply_g1(point: G1Point, private_key: PrivateKey):
    return multiply(point, private_key.scalar)


def multiply_g2(point: G2Point, private_key: PrivateKey):
    return multiply(point, private_key.scalar)


def hex_str_to_g1(string: hex_str):
    serialised_point = bytes_from_hex(string)
    return compressed_bytes_to_g1(serialised_point)


def g1_to_hex_str(point: G1Point):
    return bytes_to_hex(compressed_g1_to_bytes(point))


def g2_to_hex_str(point: G2Point):
    return bytes_to_hex(compressed_g2_to_bytes(point))


def hex_str_to_g2(string: hex_str):
    serialised_point = bytes_from_hex(string)
    return compressed_bytes_to_g2(serialised_point)


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
