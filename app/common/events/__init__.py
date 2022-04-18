from concurrent.futures import ThreadPoolExecutor

from blockchain.models import Block

pool = ThreadPoolExecutor(max_workers=5)

def handle_post_block_validation(block: Block):
    pass
