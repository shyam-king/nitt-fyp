import time

from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods 

from django.http import  JsonResponse

from common.events import register_event_handler
from common.events import auction_events
from common.util.identity import get_my_identity
from common.util.blocks import create_new_block, get_latest_block, save_block, publish_block

from blockchain.models import BlockTypes
from identity.models import Identities
from peer.models import Auction

import json

# event handlers
register_event_handler(BlockTypes.NEW_AUCTION, auction_events.new_auction_event)
register_event_handler(BlockTypes.PARTICIPATE_IN_AUCTION, auction_events.participate_auction_event)
register_event_handler(BlockTypes.AUCTION_STATE_CHANGE, auction_events.change_auction_state_event)
register_event_handler(BlockTypes.SUBMITTED_BID, auction_events.submitted_bid_event)
register_event_handler(BlockTypes.MCP_EVALUATED, auction_events.MCP_evaluated_event)
register_event_handler(BlockTypes.MATCHED_BID_RESULT, auction_events.matched_bid_result_event)
register_event_handler(BlockTypes.RISK_EVALUATED, auction_events.risk_analysis_result_event)

# routes

@csrf_exempt
@require_http_methods(["POST"])
def join_auction(request):
    data = json.loads(request.body)
    auction_id = data["auction_id"]
    node_index = data["node_index"]
    pv_factor = data["pv_installment_factor"]

    my_identity = get_my_identity()
    auction = Auction.objects.filter(auction_id=auction_id).get()
    
    block_data = json.dumps({
        "alias": my_identity.alias,
        "auction_id": auction_id,
        "node_index": node_index,
        "pv_installment_factor": pv_factor,
    }).encode("utf-8")

    block_attr = {
        "auction_id": auction_id,
    }

    block, block_keys, block_attributes = create_new_block(
        block_data,
        BlockTypes.PARTICIPATE_IN_AUCTION,
        block_attr,
        my_identity,
        [my_identity, Identities.objects.filter(alias=auction.auction_leader).get()],
        get_latest_block(),
    )    

    publish_block(block, block_keys, block_attributes)

    return JsonResponse({"message": "ok"})    


@csrf_exempt
@require_http_methods(["POST"])
def bid(request):
    data = json.loads(request.body)
    auction_id = data["auction_id"]

    auction = Auction.objects.filter(auction_id = auction_id).get()
    
    my_identity = get_my_identity()
    alias = my_identity.alias

    units = data["units"]
    rate = data["rate"]

    timestamp = int(time.time())

    block_data = json.dumps({
        "auction_id": auction_id,
        "alias": alias,
        "units": units,
        "rate": rate,
        "timestamp": timestamp,
    }).encode("utf-8")
    block_attr = {
        "auction_id": auction_id,
        "type": "bid",
    }

    block, block_keys, block_attributes = create_new_block(
        block_data,
        BlockTypes.SUBMITTED_BID,
        block_attr,
        my_identity,
        [my_identity, Identities.objects.filter(alias=auction.auction_leader).get()],
        get_latest_block(),
    )

    publish_block(block, block_keys, block_attributes)

    return JsonResponse({"message": "ok"})
