from concurrent.futures import ThreadPoolExecutor, wait
import os.path as  path
import pandas as pd 
import json

import logging
logger = logging.getLogger(__name__)

from common.util.identity import is_genesis_node, get_my_identity
from common.util.blocks import get_latest_block, create_new_block, publish_block

from peer.models import AuctionParticipant, Auction
from blockchain.models import BlockTypes
from identity.models import Identities

pool = ThreadPoolExecutor(max_workers=5)

def calculate_cvar(current_month = 1, current_hour = 14):
    weather_data = pd.read_csv(path.join(path.dirname(__file__), "res/weatherdata_raw.csv"))
    current_hour -= 5

    required_data = weather_data[(weather_data.Month == current_month) & (weather_data.Hour == current_hour)].copy().reset_index(drop=True)
    pv = required_data[["Month", "Hour", "pv"]].copy()

    n = pv.shape[0]
    pv.sort_values(by=["pv"], ascending=[True], inplace=True)

    pv = pv.reset_index(drop=True)
    cvar95 = pv.loc[pv.index <= (1-0.95)*n].pv.sum()/(1-0.95)/n

    return cvar95

def __publish_risk_analysis_result(auction_id, alias: str, units: float):
    logger.info(f"publishing risk analysis for alias/{alias} for auction/{auction_id}")

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
        BlockTypes.RISK_EVALUATED,
        block_attr,
        my_identity,
        [my_identity, Identities.objects.filter(alias=alias).get()],
        get_latest_block(),
    )    
    
    publish_block(block, block_keys, block_attributes)


def algorithm(auction_id: str, buyers: pd.DataFrame, sellers: pd.DataFrame, alias_map: dict):
    if not is_genesis_node():
        logger.info(f"skipping risk algorithm since not genesis")
        return 
    
    logger.info(f"running risk analysis algorithm for auction/{auction_id}")

    cvar = calculate_cvar()

    auction = Auction.objects.filter(auction_id=auction_id).get()

    for seller in sellers.itertuples():
        alias = alias_map[seller[sellers.columns.get_loc("Node number") + 1]]
        auction_participant = AuctionParticipant.objects.filter(auction=auction, alias=alias).get()
        installed_factor = auction_participant.pv_installment_factor

        risk_value = cvar * installed_factor

        if abs(seller.P_matched) > abs(risk_value):
            __publish_risk_analysis_result(auction_id, alias, abs(seller.P_matched) - abs(risk_value))
        else:
            __publish_risk_analysis_result(auction_id, alias, 0)

    for buyer in buyers.itertuples():
        alias = alias_map[buyer[buyers.columns.get_loc("Node number")+1]]
        __publish_risk_analysis_result(auction_id, alias, 0)




