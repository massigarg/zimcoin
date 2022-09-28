from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec, utils


class User:
    def __init__(self, balance, nonce):
        self.balance = balance
        self.nonce = nonce
        self.private_key = ec.generate_private_key(
            ec.SECP256K1())  # private key
        self.public_key = self.private_key.public_key()  # public key

    def __repr__(self):
        return f"""
        User Balance: {self.balance} \n
        User Nonce: {self.nonce} \n
        User Address: {self.address.hex()}

        """

    # The public key is not in a format that can be exchanged. We encode it in a process called serialization.
    # We will use the DER encoding format. DER stands for Distinguished Encoding Rules

    def public_key_DER(self):
        """Encoding public key in DER format
        """
        der_encoded_public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return der_encoded_public_key

    def public_key_PEM(self):
        """Encoding public key in PEM format
        """
        pem_encoded_public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_encoded_public_key

    def private_key_PEM(self):
        """Encoding private key in PEM fromat
        """
        pem_encoded_private_key = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem_encoded_private_key

    def private_key_DER(self):
        """Encoding private key in DER fromat
        """
        der_encoded_private_key = self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return der_encoded_private_key

    def save_key(self, filename):
        """_This fucntion saves locally the private key in PEM format
        """
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(filename, 'wb') as pem_out:
            pem_out.write(pem)

    @staticmethod
    def load_key(filename):
        """ This function load the saved  PEM private key
        """
        with open(filename, 'rb') as pem_in:
            pemlines = pem_in.read()
        private_key = load_pem_private_key(pemlines, None, default_backend())
        return private_key

    @property
    def address(self):
        """Creating the user address using SHA1 from the public key
        """
        digest = hashes.Hash(hashes.SHA1())  # hashing the empty string
        digest.update(self.public_key_DER())
        hash_pk_SHA1 = digest.finalize()
        return hash_pk_SHA1


class UserState():
    def __init__(self, balance, nonce) -> None:
        self.balance = balance
        self.nonce = nonce

    def __repr__(self):
        return f"""
        User Balance: {self.balance}
        User Nonce: {self.nonce}
        """

    def increase_balance(self, amount):
        """Increase User balance by amount
        """
        self.balance += amount

    def decrease_balance(self, amount):
        """Decrease User balance by amount
        """
        self.balance -= amount


# me = User(0, -1)

# print(me.address)
# print(me.address.hex())
