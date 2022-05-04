from blockchain.models import Block, BlockKey

from common.util.blocks import read_block_data

from peer.models import Auction, AuctionParticipant

import json

import logging
logger = logging.getLogger(__name__)

def new_auction_event(block: Block, block_key: BlockKey):
    logger.info(f"handling new auction")
    try:
        auction_data = read_block_data(block, block_key)
        auction_data = json.loads(auction_data)

        auction = Auction(
            auction_id=auction_data["auction_id"],
            timestamp=auction_data["timestamp"],
            status=Auction.States.CREATED,
            auction_leader=block.source,
        )

        auction.save()
        logger.info(f"created auction/${auction.auction_id}")
    except Exception as e:
        logger.error(f"error while processing new auction event from block/{block.block_id}")
        logger.error(e)    


def participate_auction_event(block: Block, block_key: BlockKey):
    logger.info(f"handling auction participation record from block/{block.block_id}")
    try:
        data = read_block_data(block, block_key)
        data = json.loads(data)

        auction_id = data["auction_id"]
        participant_alias = data["alias"]

        auction = Auction.objects.filter(auction_id=auction_id).get()
        if auction.status != Auction.States.CREATED:
            logger.warn(f"not adding participant/{participant_alias} to auction/{auction_id} since it is not in {Auction.States.CREATED} state")
            return 
        
        participant = AuctionParticipant(auction=auction, alias=participant_alias)
        participant.save()

        logger.info(f"added participant/{participant_alias} to auction/{auction}")

    except Exception as e:
        logger.error(f"error while handling auction participation event for block/{block.block_id}")
        logger.error(e)    