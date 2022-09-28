from copy import deepcopy
from user import *
from transactions import *
from cryptography.hazmat.primitives import hashes
# from time import time
import os
from multiprocessing import Pool
import time
# import multiprocessing
# import math

block_reward = 10_000


class Block:
    def __init__(self, previous, height, miner, transactions, timestamp: int, difficulty, block_id, nonce) -> None:
        self.previous = previous
        self.height = height
        self.miner = miner
        self.transactions = transactions
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.block_id = block_id
        self.nonce = nonce

    def verify_and_get_changes(self, difficulty: int, previous_user_states: dict) -> dict:
        """This function returns a dictionary of changed states

        Args:
            difficulty (int): difficulty
            previous_user_states (dict): previous_user_states

        Raises:
            Exception: Raises exception if difficulty doesn't match
            Exception: Raises exception if block_ids don't match
            Exception: Raises exception if transactions lenght >20
            Exception: Raises exception if miner != 20 bytes

        Returns:
            dict: dictionary of changed states
        """

        # difficulty
        if difficulty != self.difficulty:
            raise Exception("Difficulty doesn't match")

        # block id
        digest = hashes.Hash(hashes.SHA256())

        if self.previous:
            digest.update(self.previous)
        if type(self.miner) == type('str'):
            self.miner = bytes.fromhex(self.miner)
        digest.update(self.miner)

        for transaction in self.transactions:
            digest.update(transaction.txid)

        digest.update(Transaction.little_endian(self.timestamp))
        digest.update(difficulty.to_bytes(
            16, byteorder="little", signed=False))
        digest.update(Transaction.little_endian(self.nonce))
        block_id = digest.finalize()

        if self.block_id != block_id:
            raise Exception("block_ids don't match")

        # transactions lenght
        if len(self.transactions) > 20:
            raise Exception("can't go past 20 transactions per block")
        # miner
        if len(self.miner) > 20:
            raise Exception("miner should have 20 bytes")

        # block_id small
        target = 2**256//difficulty
        if int.from_bytes(self.block_id, byteorder="big", signed=False) > target:
            raise Exception("Invalid proof of work")

        # this avoid changing the state of the input state
        states = deepcopy(previous_user_states)
        if states:
            try:
                miner = states[self.miner]
            except:
                states[self.miner] = miner = UserState(0, -1)

            miner.balance += block_reward  # coinbase reward
            for transaction in self.transactions:
                sender = states[transaction.sender_hash]

                # first transaction without recipient in states
                try:
                    if states[transaction.recipient_hash]:
                        recipient = states[transaction.recipient_hash]
                except:
                    states[transaction.recipient_hash] = UserState(
                        0, -1)
                    recipient = states[transaction.recipient_hash]

                # verification
                if transaction.verify(sender.balance, sender.nonce):
                    transaction.balance_update(sender, recipient)
                    miner.balance += transaction.fee

            return states

        # genesis block
        else:
            previous_user_states[self.miner] = UserState(0, -1)
            previous_user_states[self.miner].balance += block_reward
            states[self.miner] = previous_user_states[self.miner]
            return states

    # please note: this function is for CW4
    def get_changes_for_undo(self, user_states_after: dict) -> dict:
        """Returns a dictionary from bytes to UserStates , mapping addresses to the  UserState  before the block was processed

        Args:
            user_states_after (dict): user_states after the block is mined

        Returns:
            dict: previous user state
        """

        states = deepcopy(user_states_after)
        if states:
            try:
                miner = states[self.miner]

            except:
                states[self.miner] = miner = UserState(0, -1)
            miner.balance -= block_reward  # coinbase reward
            for transaction in self.transactions:
                sender = states[transaction.sender_hash]

                # first transaction without recipient in states
                try:
                    if states[transaction.recipient_hash]:
                        recipient = states[transaction.recipient_hash]
                except:
                    states[transaction.recipient_hash] = UserState(
                        0, -1)
                    recipient = states[transaction.recipient_hash]

                transaction.revert_balance_update(sender, recipient)
                miner.balance -= transaction.fee

            return states

        return states


def _mine_block(args):
    """mine_block helper function
    """

    previous, height, miner, transactions, timestamp, difficulty, nonce_range = args

    target = 2**256//difficulty

    # starting to create block digest
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(previous))
    digest.update(miner)
    for transaction in transactions:
        digest.update(transaction.txid)
    digest.update(Transaction.little_endian(timestamp))
    digest.update(difficulty.to_bytes(
        16, byteorder="little", signed=False))

    for nonce in range(nonce_range[0], nonce_range[1]):
        digest_copy = digest.copy()
        # add the nonce to the end of the block id
        digest_copy.update(Transaction.little_endian(nonce))
        block_id = digest_copy.finalize()

        block_id_big = int.from_bytes(block_id, byteorder="big", signed=False)

        if block_id_big <= target:
            return Block(
                previous,
                height,
                miner,
                transactions,
                timestamp,
                difficulty,
                block_id,
                nonce
            )
    return None


def mine_block(previous: dict, height: int, miner: bytes, transactions: list, timestamp: int, difficulty: int, *args) -> Block:
    """Returns a block

    Args:
        previous (dict): Previous states
        height (int): block height
        miner (bytes): miner address
        transactions (list): list of transactions
        timestamp (int): timestamp
        difficulty (int): difficulty

    Returns:
        Block: mined block
    """
    cutoff_time = args
    # cutoff_time = int(cutoff_time)

    n_processes = os.cpu_count()
    # here micro-batches are used to boost multiprocessing functionality.
    # Too small batches incur overhead from starting parallel jobs,
    # too large size causes other processes to do extra work while one process already found an answer
    batch_size = int(2.5e5)

    with Pool(n_processes) as pool:

        nonce = 0
        print(time.time())
        print(cutoff_time)
        # print(time.time()-cutoff_time)

        while time.time() < cutoff_time[0]:

            # creating nonce ranges based on cpu processors
            nonce_ranges = [
                (nonce + i * batch_size, nonce + (i+1) * batch_size)
                for i in range(n_processes)
            ]

            params = [
                (previous, height, miner, transactions, timestamp, difficulty, nonce_range) for nonce_range in nonce_ranges
            ]

            # Using imap_unordered will return the result immediately from any of the workers without waiting for all of them to be completed.
            for result in pool.imap_unordered(_mine_block, params, chunksize=1):
                if isinstance(result, Block):
                    # print(
                    #     f"Block ID: {result.block_id.hex()}, Nonce: {result.nonce}")
                    return result

            nonce += n_processes * batch_size


# # UNCOMMENT FOR SINGLE PROCESSING
# def mine_block(previous, height, miner, transactions, timestamp, difficulty, *args):

#     digest = hashes.Hash(hashes.SHA256())
#     digest.update(bytes(previous))
#     digest.update(miner)
#     for transaction in transactions:
#         digest.update(transaction.txid)
#     digest.update(Transaction.little_endian(timestamp))
#     digest.update(difficulty.to_bytes(16, byteorder="little", signed=False))

#     max_nonce = 2**64-1
#     # calculate the difficulty target
#     target = 2**256//difficulty

#     for nonce in range(max_nonce):
#         digestn = digest.copy()
#         # add the nonce to the end of the block id
#         digestn.update(Transaction.little_endian(nonce))
#         block_id = digestn.finalize()
#         block_id_big = int.from_bytes(block_id, byteorder="big", signed=False)
#         if block_id_big <= target:
#             return Block(
#                 previous,
#                 height,
#                 miner,
#                 transactions,
#                 timestamp,
#                 difficulty,
#                 block_id,
#                 nonce
#             )


# if __name__ == "__main__":
#     def calculate_sha1_hash(public_key):
#         digest = hashes.Hash(hashes.SHA1())
#         digest.update(public_key)
#         return digest.finalize()

#     def private_key_to_public_key(private_key):
#         return private_key.public_key().public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)

#     alice = ec.generate_private_key(ec.SECP256K1)
#     alice_address = calculate_sha1_hash(
#         private_key_to_public_key(alice))

#     block_1 = mine_block(
#         bytes(32), 0, alice_address, [], int(time.time()), 100, time.time()+15.0)
#     states = block_1.verify_and_get_changes(100, dict())
#     print((states[alice_address].balance))
