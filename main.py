import sys
import time
import tornado
from transactions import *
from blockchain_state import *
from blocks import *
from miner import Miner
from node import Node
from connections import run_server, remote_connection

import nest_asyncio
nest_asyncio.apply()

MINER_ADDRESS = b'o\x12.\xb9<4Wp\xa60\xc2\x83E\xf26\x16\xfd\\\xd0\xe6'

if __name__ == "__main__":
    if len(sys.argv) == 1:
        REMOTE_NODES = ["ws://node.zimcoin.org:46030/"]
        node = Node.start("./blocks.sqlite").proxy()
        miner = Miner.start(node, MINER_ADDRESS).proxy()

        for remote in REMOTE_NODES:
            remote_connection(node, remote)
        miner.start_mining()

        tornado.ioloop.IOLoop.current().start()
    elif sys.argv[1] == 'server':
        PORT = 46030
        REMOTE_NODES = []
        node = Node.start("./blocks.sqlite").proxy()
        miner = Miner.start(node, MINER_ADDRESS).proxy()
        miner.start_mining()
        run_server(node, PORT)
    else:
        print("Unknown command")
