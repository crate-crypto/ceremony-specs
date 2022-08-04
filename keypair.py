from dataclasses import dataclass
from bls import PrivateKey, PublicKey


@dataclass
class KeyPair:
    private_key: PrivateKey
    public_key: PublicKey

    def __init__(self, secret: int) -> None:
        private_key = PrivateKey(secret)

        self.public_key = private_key.to_public_key()
        self.private_key = private_key

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
