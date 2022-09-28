import unittest
from transactions import *
from user import *
from cryptography.hazmat.primitives.asymmetric import ec, utils


class TransactionTest(unittest.TestCase):

    def test_verify_signature(self):
        """ Calling create_signed_transaction to make a test transaction and that the transaction.verify call succeeds (when provided with a sender_balance which is sufficiently high and sender_previous_nonce = transaction.nonce - 1 ).
        """

        sender = User(50, 4)
        recipient = User(30, 7)

        tx = create_signed_transaction(
            sender.private_key,  # private key
            # recipient hash
            recipient.address,
            10,  # amount
            2,  # fee
            sender.nonce  # nonce
        )

        self.assertTrue(tx.verify(sender.balance, (sender.nonce-1)))

    def test_txid(self):
        """Generating a valid transaction and checking that modifying any of the fields causes transaction.verify to raise an exception due to an invalid txid .
        """
        sender = User(50, 4)
        recipient = User(30, 7)

        # valid transaction
        tx = create_signed_transaction(
            sender.private_key,  # private key
            # recipient hash
            recipient.address,
            10,  # amount
            2,  # fee
            sender.nonce  # nonce
        )

        # changing sender_private_key
        tx_sender = tx
        sender_2 = User(30, 8)
        tx_sender.sender_hash = sender_2.address

        with self.assertRaisesRegex(Exception, "Transaction failed. Txid should be the the hash of the other fields in Transaction"):
            tx_sender.verify(sender.balance, (sender.nonce-1))

        # changing recipient_hash
        tx_recipient = tx
        recipient_2 = User(30, 8)
        tx_recipient.recipient_hash = recipient_2.address
        with self.assertRaisesRegex(Exception, "Transaction failed. Txid should be the the hash of the other fields in Transaction"):
            tx_recipient.verify(sender.balance, (sender.nonce-1))

        # changing signature
        tx_signature = tx

        tx_signature.signature = bytes(64)

        with self.assertRaisesRegex(Exception, "Transaction failed. Txid should be the the hash of the other fields in Transaction"):
            tx_signature.verify(sender.balance, (sender.nonce-1))

    def test_amount(self):
        """Generating a valid transaction, changing the amount field, regenerating the txid so it is valid again. Checking that transaction.verify raises an exception due to an invalid signature.
        """

        sender = User(50, 4)
        recipient = User(30, 7)

        # valid transaction
        tx = create_signed_transaction(
            sender.private_key,  # private key
            # recipient hash
            recipient.address,
            10,  # amount
            2,  # fee
            sender.nonce  # nonce
        )

        # changing amout
        tx.amount = 20

        # regenerating the txid with different amount
        tx.txid = Transaction.create_txid(
            sender.address,
            recipient.address,
            sender.public_key_DER(),
            tx.amount,
            tx.fee,
            tx.nonce,
            tx.signature
        )

        with self.assertRaisesRegex(Exception, "Transaction failed. Signature should be a valid signature"):
            tx.verify(sender.balance, (sender.nonce-1))

    def test_incorrect_nonce_and_balance(self):
        """
        Generate a valid transaction, check that transaction.verify raises an exception if either the sender_balance is too low or sender_previous_nonce is incorrect.
        """

        # balance too low
        sender = User(50, 4)
        recipient = User(30, 7)
        tx = create_signed_transaction(
            sender.private_key,  # private key
            # recipient hash
            recipient.address,
            60,  # amount
            2,  # fee
            sender.nonce  # nonce
        )

        with self.assertRaisesRegex(Exception, "Balance too small"):
            tx.verify(sender.balance, (sender.nonce-1))

    def test_A_B_transaction(self):
        """Generate two private keys, A and B . Use A to generate a valid transaction. Replace the signature with a signature created using B . Regenerate the txid and confirm that transaction.verify fails with an invalid signature.
        """

        user_A = User(20, 5)
        user_B = User(30, 10)
        user_C = User(70, 8)

        tx_A = create_signed_transaction(
            user_A.private_key,
            user_C.address,
            10,
            2,
            user_A.nonce
        )

        # creating the a message for B to sign
        digest = hashes.Hash(hashes.SHA256())
        digest.update(user_C.address)
        digest.update(Transaction.little_endian(tx_A.amount))
        digest.update(Transaction.little_endian(tx_A.fee))
        digest.update(Transaction.little_endian(tx_A.nonce))
        message = digest.finalize()

        # new signature from user_B
        tx_A.signature = user_B.private_key.sign(
            message,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )

        # Regenerating txid
        tx_A.txid = Transaction.create_txid(
            user_A.address,
            user_C.address,
            user_A.public_key_DER(),
            tx_A.amount,
            tx_A.fee,
            tx_A.nonce,
            tx_A.signature
        )

        with self.assertRaisesRegex(Exception, "Transaction failed. Signature should be a valid signature"):
            tx_A.verify(user_A.balance, (user_A.nonce-1))

    def test_transaction(self):
        """Check that the following transaction verifies successfully (when using sender_balance = 20 , sender_previous_nonce = 4 )
        """

        tx = Transaction(
            bytes.fromhex("3df8f04b3c159fdc6631c4b8b0874940344d173d"),
            bytes.fromhex("5c1499a0484ace2f731b0afb83241e15f0e168ca"),
            bytes.fromhex("3056301006072a8648ce3d020106052b8104000a" +
                          "03420004886ed03cb7ffd4cbd95579ea2e202f1d" +
                          "b29afc3bf5d7c2c34a34701bbb0685a7b535f1e6" +
                          "31373afe8d1c860a9ac47d8e2659b74d437435b0" +
                          "5f2c55bf3f033ac1"),
            10,
            2,
            5,
            bytes.fromhex("3046022100f9c076a72a2341a1b8cb68520713e1" +
                          "2f173378cf78cf79c7978a2337fbad141d022100" +
                          "ec27704d4d604f839f99e62c02e65bf60cc93ae1"
                          "735c1ccf29fd31bd3c5a40ed"),
            bytes.fromhex("ca388e0890b71bd1775460d478f26af3776c9b4f" +
                          "6c2b936e1e788c5c87657bc3"))

        self.assertTrue(tx.verify(sender_balance=20, sender_previous_nonce=4))


if __name__ == "__name__":
    unittest.main()
