from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec, utils
from user import *


class Transaction:
    def __init__(self, sender_hash, recipient_hash, sender_public_key, amount, fee, nonce, signature, txid):
        # The public key hash of the user sending the funds
        self.sender_hash = sender_hash
        # The public key hash of the user receiving the fund
        self.recipient_hash = recipient_hash
        # A byte array representing the public key of the user sending the funds
        self.sender_public_key = sender_public_key
        self.amount = amount  # The amount of funds being sent from the sender's address
        self.fee = fee  # The amount of funds paid as a mining fee in this transaction
        # A 64 bit number, this should increase by 1 for each transfer made by the sender
        self.nonce = nonce
        # A signature, created by the sender, confirming that they consent to this transaction
        self.signature = signature
        self.txid = txid  # The transaction id, this is a hash of the other fields of the transaction
        self.verified_status = False  # Transaction verification status

    # readeable print of the class

    def __repr__(self) -> str:
        return f"""\n
            From: {self.sender_hash.hex()} \n
            To: {self.recipient_hash.hex()} \n
            Value: {self.amount} \n
            Fee: {self.fee} \n
            Signature: {self.signature.hex()}
            """

    @staticmethod
    def little_endian(value):
        """Zimcoin, like most other cryptocurrencies, uses 'little endian' integers, meaning that, when
            encoding numbers as a list of bytes, the first byte is the least significant
        """
        try:
            return (value).to_bytes(8, byteorder="little", signed=False)
        except AttributeError:
            print("Sorry, 1 Zimcoin is the smallest unit of currency. It is impossible to send someone half a Zimcoin.")
            return bytes(False)

    @staticmethod
    def create_txid(sender_hash, recipient_hash, sender_public_key, amount, fee, nonce, signature):
        """ Calculation of Transaction ID.
        The txid should be a SHA-256 hash of the following data:
        * sender_hash
        * recipient_hash
        * sender_public_key
        * amount
        * fee
        * nonce
        * signature
        """
        try:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(sender_hash)
            digest.update(recipient_hash)
            digest.update(sender_public_key)
            digest.update(Transaction.little_endian(amount))
            digest.update(Transaction.little_endian(fee))
            digest.update(Transaction.little_endian(nonce))
            digest.update(signature)
            txid = digest.finalize()
            return txid
        except Exception as e:
            print("Invalid txid")

    @staticmethod
    def message(recipient_hash, amount, fee, nonce):
        """This is the message that needs to be prepared before sign
        """
        try:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(recipient_hash)
            digest.update(Transaction.little_endian(amount))
            digest.update(Transaction.little_endian(fee))
            digest.update(Transaction.little_endian(nonce))
            message = digest.finalize()
            return message
        except Exception as e:
            print(e)
            print("Invalid message")

    def verify_signature(self):
        """Signature verification
        """
        try:
            deserialized_public_key = load_der_public_key(
                self.sender_public_key)
            deserialized_public_key.verify(
                self.signature, Transaction.message(
                    self.recipient_hash, self.amount, self.fee, self.nonce),
                ec.ECDSA(utils.Prehashed(hashes.SHA256()))
            )
            return True
        except Exception as e:
            print(e)
            return False

    def verify(self, sender_balance, sender_previous_nonce):
        """Verification:

        * sender_hash  and  recipient_hash  should both be 20 bytes long
        * sender_hash  should be the SHA-1 hash of  sender_public_key
        * amount  should be a whole number between 1 and  sender_balance  inclusive
        * fee  should be a whole number between 0 and  amount  inclusive
        * nonce  should be  sender_previous_nonce + 1
        * txid  should be the the hash of the other fields in  Transaction , as described below
        * signature  should be a valid signature, as described below
        """

        fail_text = "Transaction failed."

        # sender_hash should be 20 bytes long
        if len(self.sender_hash) != 20:
            raise Exception(
                f"{fail_text} Sender_hash should be 20 bytes long")

        # recipient_hash should be 20 bytes long
        if len(self.recipient_hash) != 20:
            raise Exception(
                f"{fail_text} Recipient_hash should be 20 bytes long")

        # amount  should be a whole number between 1 and  sender_balance  inclusive
        if not (self.amount % 1 == 0 and self.amount <= sender_balance):
            raise Exception("Balance too small")

        # fee should be a whole number between 0 and amount inclusive
        if not (self.fee % 1 == 0 and self.fee <= self.amount):
            raise Exception(
                f"{fail_text} Fee should be a whole number between 0 and amount inclusive")

        # nonce should be sender_previous_nonce + 1
        if self.nonce != sender_previous_nonce + 1:
            raise Exception("Invalid nonce")

        # txid should be the the hash of the other fields in Transaction
        if self.txid != self.create_txid(self.sender_hash, self.recipient_hash, self.sender_public_key, self.amount, self.fee, self.nonce, self.signature):
            raise Exception(
                f"{fail_text} Txid should be the the hash of the other fields in Transaction")

        # sender_hash  should be the SHA-1 hash of  sender_public_key
        digest = hashes.Hash(hashes.SHA1())
        digest.update(self.sender_public_key)
        sender_pk_SHA1 = digest.finalize()
        if self.sender_hash != sender_pk_SHA1:
            raise Exception(
                "Sender_hash should be the SHA-1 hash of sender_public_key")

        # signature should be a valid signature
        if not self.verify_signature():
            raise Exception(
                f"{fail_text} Signature should be a valid signature")

        self.verified_status = True

        return self.verified_status

    def balance_update(self, sender, recipient):
        """Updates sender and recipient balance
        """
        sender.decrease_balance(self.amount)
        recipient.increase_balance(self.amount-self.fee)
        sender.nonce += 1

    def revert_balance_update(self, sender, recipient):
        """Revert sender and recipient balance
        """
        sender.increase_balance(self.amount)
        recipient.decrease_balance(self.amount-self.fee)
        sender.nonce -= 1


def create_signed_transaction(sender_private_key: ec.EllipticCurvePrivateKey, recipient_hash: bytearray, amount: int, fee: int, nonce: int) -> Transaction:
    """This function creates a signed transaction

    Args:
        sender_private_key (ec.EllipticCurvePrivateKey)
        recipient_hash (bytearray)
        amount (int)
        fee (int)
        nonce (int)

    Returns:
        transaction
    """
    # sender_public_key
    sender_public_key = sender_private_key.public_key()

    # der_sender_public_key
    der_sender_public_key = sender_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # sender_address
    digest = hashes.Hash(hashes.SHA1())
    digest.update(der_sender_public_key)
    sender_hash = digest.finalize()

    # message preparation
    digest = hashes.Hash(hashes.SHA256())
    digest.update(recipient_hash)
    digest.update(Transaction.little_endian(amount))
    digest.update(Transaction.little_endian(fee))
    digest.update(Transaction.little_endian(nonce))
    message = digest.finalize()

    # sender signature for this message
    sender_signature = sender_private_key.sign(
        message,
        # note: message is already hashed
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )

    # creating a transaction id with sender signature
    txid = Transaction.create_txid(
        sender_hash, recipient_hash, der_sender_public_key, amount, fee, nonce, sender_signature)

    # create transaction
    tx = Transaction(sender_hash, recipient_hash, der_sender_public_key,
                     amount, fee, nonce, sender_signature, txid)

    return tx
