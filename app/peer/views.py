from venv import create
from django.shortcuts import render

from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods 

from django.http import HttpResponse, JsonResponse

from common.events import register_event_handler
from common.events import auction_events
from common.util.identity import get_my_identity
from common.util.blocks import create_new_block, get_latest_block, save_block, validate_block, publish_block

from blockchain.models import BlockTypes
from identity.models import Identities
from peer.models import Auction

import json


# event handlers
register_event_handler(BlockTypes.NEW_AUCTION, auction_events.new_auction_event)
register_event_handler(BlockTypes.PARTICIPATE_IN_AUCTION, auction_events.participate_auction_event)


# routes

@csrf_exempt
@require_http_methods(["POST"])
def join_auction(request):
    data = json.loads(request.body)
    auction_id = data["auction_id"]

    my_identity = get_my_identity()
    auction = Auction.objects.filter(auction_id=auction_id).get()
    
    block_data = json.dumps({
        "alias": my_identity.alias,
        "auction_id": auction_id,
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

    validate_block(block, block_keys)
    save_block(block, block_keys, block_attributes)
    publish_block(block, block_keys, block_attributes)

    return JsonResponse({"message": "ok"})    

