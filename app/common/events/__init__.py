from concurrent.futures import ThreadPoolExecutor, wait

from blockchain.models import Block, BlockKey
from common.util.identity import get_my_identity

import logging
logger = logging.getLogger(__name__)

pool = ThreadPoolExecutor(max_workers=5)

block_type_event_registry = {}

block_locks={}

def register_event_handler(event, handler):
    block_type_event_registry[event] = block_type_event_registry.get(event, []) + [handler]
    logging.info(f"added handler to event/{event}")


def handle_post_block_commit(block: Block):
    if block.block_id not in block_locks:
        block_locks[block.block_id] = None
        logger.info(f"scheduling post commit for {block.block_id}")
        keys = BlockKey.objects.filter(block=block).all()
        pool.submit(_post_commit_block_handler, block, keys)


def _post_commit_block_handler(block: Block, keys: list[BlockKey]):
    logger.info(f"handling post commit for {block.block_id}")
    try:
        my_identity = get_my_identity()
        keys = list(filter(lambda x: x.target_alias == my_identity.alias, keys))

        if len(keys) == 0:
            logger.info(f"skipping post processing of block/${block.block_id} since there is no corresponding key for this node")
            return
        key = keys[0]

        p = []
        if len(block_type_event_registry.get(block.block_type, [])) == 0:
            logger.warn(f"no handlers attached for event/{block.block_type} for block/{block.block_id}")
        else:   
            for handler in block_type_event_registry[block.block_type]:
                p.append(pool.submit(handler, block, key))
            wait(p)

        logger.info(f"post commit processing of block/{block.block_id} complete")
    except Exception as e:
        logger.error(f"error post commit for {block.block_id}:")
        logger.error(e)
   
        


