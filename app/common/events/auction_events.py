import traceback
from concurrent.futures import ThreadPoolExecutor

from blockchain.models import Block, BlockKey

from common.util.blocks import read_block_data
from common.algorithms import energy_matching

from peer.models import Auction, AuctionParticipant, Bid, MCPResult, BidMatch

import json

import logging
logger = logging.getLogger(__name__)

pool = ThreadPoolExecutor(max_workers=5)

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
        node_index = data["node_index"]

        auction = Auction.objects.filter(auction_id=auction_id).get()
        if auction.status != Auction.States.CREATED:
            logger.warn(f"not adding participant/{participant_alias} to auction/{auction_id} since it is not in {Auction.States.CREATED} state")
            return 
        
        participant = AuctionParticipant(auction=auction, alias=participant_alias, node=node_index)
        participant.save()

        logger.info(f"added participant/{participant_alias} to auction/{auction}")

    except Exception as e:
        logger.error(f"error while handling auction participation event for block/{block.block_id}")
        logger.error(e)    


def change_auction_state_event(block: Block, block_key: BlockKey):
    logger.info(f"handling auction state change event for block/{block.block_id}")
    try:
        data = read_block_data(block, block_key)
        data = json.loads(data)
        auction_id = data["auction_id"]
        state = data['state']

        auction = Auction.objects.filter(auction_id=auction_id).get()
        auction.status = state 
        auction.save()

        logger.info(f"updated auction/{auction_id} state to {state}")

        if state == Auction.States.HOUR_AHEAD_BIDDING_FINISHED:
            pool.submit(energy_matching.algorithm, auction_id)
            
    except Exception as e:
        logger.error(f"error occured while handling auction state change event for block/{block.block_id}")
        logger.error(traceback.format_exc(e))


def submitted_bid_event(block: Block, block_key: BlockKey):
    logger.info(f"handling submitted bid event for block/{block.block_id}")
    try:
        data = read_block_data(block, block_key)
        data = json.loads(data)
        auction_id = data["auction_id"]
        alias = data["alias"]
        units = data["units"]
        rate = data["rate"]
        timestamp = data["timestamp"]

        auction = Auction.objects.filter(auction_id=auction_id).get()
        if auction.status == Auction.States.HOUR_AHEAD_BIDDING_STARTED:
            bid_type = Bid.Types.HOUR_AHEAD
        elif auction.status == Auction.States.ADJUSTMENT_BIDDING_STARTED:
            bid_type = Bid.Types.ADJUSTMENT
        else:
            logger.error(f"invalid state={auction.status} of auction/{auction_id} to accept bid from block/{block.block_id}")
            return

        bid = Bid(
            auction=auction,
            alias=alias,
            bid_type=bid_type,
            units=units,
            rate=rate,
            timestamp=timestamp
        )
        bid.save()
        logger.log(f"bid from {alias} successfully registered for auction/{auction_id}")
    except Exception as e:
        logger.error(f"error occured while handling submitted bid event for block/{block.block_id}")
        logger.error(traceback.format_exc(e))

def MCP_evaluated_event(block: Block, block_key: BlockKey):
    try:
        data = read_block_data(block, block_key)
        data = json.loads(data)

        auction_id = data["auction_id"]
        mcp = data["mcp"]

        auction = Auction.objects.filter(auction_id=auction_id).get()

        result = MCPResult(auction=auction, mcp=mcp)
        result.save()
    except Exception as e:
        logger.error(f"error occured while handling MCP_evaluated_event for block/{block.block_id}")
        logger.error(traceback.format_exc(e))
    
def matched_bid_result_event(block: Block, block_key: BlockKey):
    try:
        data = read_block_data(block, block_key)
        data = json.loads(data)

        auction_id = data["auction_id"]
        alias = data["alias"]
        units = data["units"]

        auction = Auction.objects.filter(auction_id=auction_id).get()

        result = BidMatch(auction=auction, alias=alias, units=units)
        result.save()
    except Exception as e:
        logger.error(f"error occured while handling matched_bid_result_event for block/{block.block_id}")
        logger.error(traceback.format_exc(e))
        