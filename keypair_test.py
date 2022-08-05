import unittest
from keypair import KeyPair


class TestKeyPair(unittest.TestCase):

    def test_keypair_smoke(self):
        """
            Checks that if we supply an integer as either a hex string or as a int
            it will product the same KeyPair
        """
        secret_hex = "0x123456"
        secret_int = 1193046
        key_from_hex = KeyPair(secret_hex)
        key_from_int = KeyPair(secret_int)
        self.assertEqual(key_from_hex.private_key, key_from_int.private_key)
        self.assertEqual(key_from_hex.public_key, key_from_int.public_key)

    def test_keypair_prepend_0x(self):
        """
            Here we show that the 0x is not needed, since when we parse a string
            to an integer, we always supply the base that the string is in

            It is included because it follows the standard used across many other 
            Ethereum repositories. If you are using Rust, you will need to remove 
            the prepended 0x, and add it back when you serialise the SRS.
        """
        secret_hex_prepended = "0x123456"
        secret_hex = "123456"

        key_from_hex = KeyPair(secret_hex_prepended)
        key_from_int = KeyPair(secret_hex)

        self.assertEqual(key_from_hex.private_key, key_from_int.private_key)
        self.assertEqual(key_from_hex.public_key, key_from_int.public_key)


if __name__ == '__main__':
    unittest.main()
