from blockchain.models import Block, BlockKey

from common.util.blocks import read_block_data

from peer.models import Auction

import json

import logging
logger = logging.getLogger(__name__)

def new_auction_event(block: Block, block_key: BlockKey):
    logging.info(f"handling new auction")
    try:
        auction_data = read_block_data(block, block_key)
        auction_data = json.loads(auction_data)

        auction = Auction(
            auction_id=auction_data["auction_id"],
            timestamp=auction_data["timestamp"],
            status=Auction.States.CREATED
        )

        auction.save()
        logging.info(f"created auction/${auction.auction_id}")
    except Exception as e:
        logging.error(f"error while processing new auction event from block/{block.block_id}")
        logging.error(e)    
