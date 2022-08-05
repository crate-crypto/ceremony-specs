from dataclasses import dataclass
from typing import Union
from bls import PrivateKey, PublicKey
from common import hex_str


@dataclass
class KeyPair:
    private_key: PrivateKey
    public_key: PublicKey

    def __init__(self, secret: Union[int, hex_str]) -> None:
        if isinstance(secret, int):
            self.private_key = PrivateKey(secret)
        elif isinstance(secret, hex_str):
            secret_as_int = int(secret, 16)
            self.private_key = PrivateKey(secret_as_int)
        else:
            raise TypeError("type is not an integer or a hexadecimal string")

        self.public_key = self.private_key.to_public_key()

    def destroy(self):
        # Once the KeyPair is no longer needed, it is important that the user deletes the private key.
        # There is no guarantee that this method will remove it from memory because the compiler is
        # allowed to memcpy anything it deems fit. Whats important here, is that the user is not
        # saving the private key and is making a conscious effort to delete it.
        #
        # Depending on your level of paranoia, a user can burn their laptop after contributing.
        #
        # In your implementation, you'll want to clear the memory
        self.private_key = PrivateKey(0)
