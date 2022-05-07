from uuid import uuid4
from venv import create
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods 
from common.util.decorators import genesis_only
from common.util.blocks import create_new_block, get_latest_block, publish_block
from blockchain.models import Block, BlockTypes
from common.util.identity import get_my_identity
from identity.models import Identities
import json
import time

@csrf_exempt
@require_http_methods(["POST"])
@genesis_only
def ping(request):
    return JsonResponse({"message": "ok"})

@csrf_exempt
@require_http_methods(["POST"])
@genesis_only
def change_auction_state(request, auction_id):
    data = json.loads(request.body)
    new_state = data["state"]

    prev_block = get_latest_block()
    block_data = json.dumps({
        "auction_id": auction_id,
        "state": new_state,
    }).encode("utf-8")
    block_type = BlockTypes.AUCTION_STATE_CHANGE
    block_attr = {
        "auction_id": auction_id,
    }
    identity = get_my_identity()
    target_identities = Identities.objects.all()

    block, block_keys, block_attributes = create_new_block(block_data, block_type, block_attr, identity, target_identities, prev_block)

    publish_block(block, block_keys, block_attributes)
    
    return JsonResponse({"message": "ok"})


    

@csrf_exempt
@require_http_methods(["POST"])
@genesis_only
def start_auction(request):
    auction_id = str(uuid4())
    prev_block = get_latest_block()
    data = json.dumps({
        "auction_id": auction_id,
        "timestamp": int(time.time()),
    }).encode("utf-8")
    block_type = BlockTypes.NEW_AUCTION
    attributes = {"auction_id": auction_id}
    identity = get_my_identity()
    target_identities = Identities.objects.all()

    auction_block, block_keys, block_attr = create_new_block(data, block_type, attributes, identity, target_identities, prev_block)    

    publish_block(auction_block, block_keys, block_attr)

    return JsonResponse({"auction_id": auction_id})

@csrf_exempt
@require_http_methods(["POST"])
@genesis_only
def create_genesis_block(request):
    my_identity = Identities.objects.get(is_self=True)
    try:
        existing_block = Block.objects.get(block_type=BlockTypes.GENESIS_BLOCK, is_committed=True)
        return JsonResponse({"message": f"genesis block already exists: {existing_block.block_id}"})
    except Block.DoesNotExist: 
        block, keys, attributes = create_new_block(b'genesis', BlockTypes.GENESIS_BLOCK, {}, my_identity, [my_identity])
        publish_block(block, keys, attributes)

    return JsonResponse({"message": "ok"})
