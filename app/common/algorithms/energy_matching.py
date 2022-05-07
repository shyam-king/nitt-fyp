import logging
import pandas as pd 
import numpy as np
import os.path as  path
from concurrent.futures import ThreadPoolExecutor, wait
import traceback
import json

logger = logging.getLogger(__name__)
pool = ThreadPoolExecutor(max_workers=5)

from common.util.identity import is_genesis_node, get_my_identity
from common.util.blocks import create_new_block, get_latest_block, validate_block, save_block, publish_block

from peer.models import Bid, Auction, AuctionParticipant
from identity.models import Identities
from blockchain.models import BlockTypes

from . import risk

def get_base_linedata() -> pd.DataFrame:
    current_dir = path.dirname(__file__)
    linedata = pd.read_excel(path.join(current_dir, "res/linedata.xlsx"))
    return linedata


def __match_bids(biddata: pd.DataFrame):
    sellers = biddata[biddata["P_promised"] > 0].copy().sort_values(by=["price"], ascending=[True]).reset_index(drop=True)
    buyers = biddata[biddata["P_promised"] <= 0].copy().sort_values(by=["price"], ascending=[True]).reset_index(drop=True)

    sellers["P_matched"] = 0
    buyers["P_matched"] = 0

    buyer_index = 0
    seller_index = 0

    b_p_promised_col = buyers.columns.get_loc("P_promised")
    b_p_matched_col = buyers.columns.get_loc("P_matched")

    s_p_promised_col = sellers.columns.get_loc("P_promised")
    s_p_matched_col = sellers.columns.get_loc("P_matched")

    Etr = np.zeros((sellers.shape[0], buyers.shape[0]))

    while buyer_index < buyers.shape[0] and seller_index < sellers.shape[0]:
        buyer_remaining = abs(buyers.iat[buyer_index, b_p_promised_col]) - abs(buyers.iat[buyer_index, b_p_matched_col])
        seller_remaining = abs(sellers.iat[seller_index, s_p_promised_col]) - abs(sellers.iat[seller_index, s_p_matched_col])

        if buyer_remaining == 0:
            buyer_index += 1
            continue
        if seller_remaining == 0:
            seller_index += 1
            continue

        txn_amount = min(buyer_remaining, seller_remaining)
        Etr[seller_index, buyer_index] = txn_amount

        buyers.iat[buyer_index, b_p_matched_col] -= txn_amount
        sellers.iat[seller_index, s_p_matched_col] += txn_amount
        
    MCP_total = biddata["price"].abs().mean()

    return MCP_total, buyers, sellers, Etr

def __publish_mcp(auction_id, mcp):
    logger.info(f"publishing mcp/{mcp} for auction/{auction_id} ")

    my_identity = get_my_identity()
    target_identities = Identities.objects.all()

    block_data = json.dumps({
        "auction_id": auction_id,
        "mcp": mcp
    }).encode("utf-8")

    block_attr = {
        "auction_id": auction_id,
    }

    block, block_keys, block_attributes = create_new_block(
        block_data,
        BlockTypes.MCP_EVALUATED,
        block_attr,
        my_identity,
        target_identities,
        get_latest_block()
    )
    
    publish_block(block, block_keys, block_attributes)

def __publish_matching_result(auction_id, alias: str, units: float):
    logger.info(f"publishing matching bid for alias/{alias} for auction/{auction_id}")

    block_data = json.dumps({
        "auction_id": auction_id,
        "participant": alias,
        "units": units,
    }).encode("utf-8")

    block_attr = {
        "auction_id": auction_id,
    }

    my_identity = get_my_identity()

    block, block_keys, block_attributes = create_new_block(
        block_data,
        BlockTypes.MATCHED_BID_RESULT,
        block_attr,
        my_identity,
        [my_identity, Identities.objects.filter(alias=alias).get()],
        get_latest_block(),
    )    
    
    publish_block(block, block_keys, block_attributes)



def get_biddata(auction_id: str):
    logger.debug(f"preparing biddata for {auction_id}")
    auction = Auction.objects.filter(auction_id=auction_id).get()
    bids = Bid.objects.filter(auction=auction).all()
    logger.debug(f"fetched bids {auction_id}")

    bid_df = {
        "Node number": [],
        "Bus number": [],
        "P_promised": [],
        "price": []
    }

    node_number = 0
    alias_map = {}

    for bid in bids:
        participant = AuctionParticipant.objects.filter(auction=auction,alias=bid.alias).get()

        bus_number = participant.node
        P_promised = bid.units
        price = bid.rate 
        node_number += 1
        alias_map[node_number] = participant.alias

        bid_df["Bus number"].append(bus_number)
        bid_df["P_promised"].append(P_promised)
        bid_df["price"].append(price)
        bid_df["Node number"].append(node_number)

    biddata = pd.DataFrame(bid_df, columns=["Node number", "Bus number", "P_promised", "price"])
    return biddata, alias_map
    
    

def algorithm(auction_id: str):
    if not is_genesis_node():
        logger.info(f"skipping energy matching algorithm since not genesis")
        return 

    logger.info(f"running energy matching for auction/{auction_id}")

    try:
        biddata, alias_map = get_biddata(auction_id)
        logger.debug(f"{auction_id}: received biddata and alias_map")

        MCP, buyers, sellers, Etr = __match_bids(biddata)
        logger.debug(f"{auction_id}: calculated MCP, buyers, selers, Etr")

        __publish_mcp(auction_id, MCP)
        
        for buyer in buyers.itertuples():
            alias = alias_map[int(buyer[buyers.columns.get_loc("Node number") + 1])]
            units = buyer.P_matched
            __publish_matching_result(auction_id, alias, units)
            
        for seller in sellers.itertuples():
            alias = alias_map[int(seller[sellers.columns.get_loc("Node number") + 1])]
            units = seller.P_matched
            __publish_matching_result(auction_id, alias, units)

        risk.algorithm(auction_id, buyers, sellers, alias_map)

    except Exception as e:
        logger.error(f"error running matching algorithm for auction/{auction_id}:")
        logger.error("".join(traceback.format_exception(e)))
