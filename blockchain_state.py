from blocks import *


class BlockchainState():
    def __init__(self, longest_chain: list, user_states: dict, total_difficulty: int) -> None:
        self.longest_chain = longest_chain
        self.user_states = user_states
        self.total_difficulty = total_difficulty

    def calculate_difficulty(self):
        """This function calculates the block difficulty

        Returns:
            int: block difficulty
        """
        if len(self.longest_chain) <= 10:
            return 1000
        else:
            # calculate total difficulty of previous 10 blocks
            total_difficulty_period = 0
            total_time_for_period = 0
            for block in self.longest_chain[-10:]:
                total_difficulty_period += block.difficulty

            # calculate total time needed for previous 10 blocks
            total_time_for_period = self.longest_chain[-1].timestamp - \
                self.longest_chain[-11].timestamp

            # zero timestamp
            try:
                # mining time of 2 min with constant hashrate
                return (total_difficulty_period//total_time_for_period)*120
            except ZeroDivisionError:
                return 1_200_000

    def verify_and_apply_block(self, block):
        """This function verify and apply the block to the chain

        Args:
            block (Block): Block

        Raises:
            Exception: Incorrect difficulty
            Exception: previous block id
        """

        # The height  of the block is the length of the longest chain
        if len(self.longest_chain) != block.height:
            raise Exception("Incorrect difficulty")
        # If the longest chain is empty then the previous  fields of the block should be 0x00...00 ,
        # otherwise it should be the block_id  of the last block in the chain
        if not self.longest_chain:
            assert block.previous == bytes(32), "previous block id"
        else:
            if block.previous != self.longest_chain[-1].block_id:
                raise Exception("previous block id")

        # If the longest chain is not empty then the timestamp of the new block should be at least the
        # timestamp of the most recent block.
        if self.longest_chain:
            if block.timestamp < self.longest_chain[-1].timestamp:
                raise Exception("previous block id")

        if self.calculate_difficulty() != block.difficulty:
            raise Exception("Incorrect difficulty")

        self.longest_chain.append(block)
        self.total_difficulty += block.difficulty
        self.user_states.update(block.verify_and_get_changes(
            block.difficulty, self.user_states))

    def undo_last_block(self):
        """This function undo the last block going back to the previous
        """
        self.total_difficulty -= self.longest_chain[-1].difficulty
        last_block = self.longest_chain.pop()
        self.user_states.update(
            last_block.get_changes_for_undo(self.user_states))


def verify_reorg(old_state: BlockchainState, new_branch: list):
    """This function verifies that the reorg is done correctly

    Args:
        old_state (BlockchainState): old chain state
        new_branch (list): new branch 

    Raises:
        Exception: Total difficulty mismatch

    Returns:
        dict: new blockchain state
    """
    new_state = BlockchainState(old_state.longest_chain.copy(
    ), old_state.user_states.copy(), old_state.total_difficulty)

    for height in range(len(new_state.longest_chain), -1, -1):
        if height == new_branch[0].height:
            for block in new_branch:
                new_state.verify_and_apply_block(block)
            if new_state.total_difficulty > old_state.total_difficulty:
                return new_state
            else:
                raise Exception("total difficulty")
        else:
            new_state.undo_last_block()
