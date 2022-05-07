from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, JsonResponse
from blockchain.models import Block, BlockKey, BlockAttribute
from identity.models import Identities
from django.shortcuts import get_object_or_404
from common.util.blocks import read_block_data, save_block, publish_block, BlockValidationFailedException, validate_block, process_query
from django.views.decorators.http import require_http_methods
import jsonschema as jsc
import json
import time
from django.views.decorators.csrf import csrf_exempt
import logging

logger = logging.getLogger(__name__)

@require_http_methods(["GET"])
def view_block(request, block_id):
    my_identity = get_object_or_404(Identities, is_self=True)
    block = get_object_or_404(Block, pk=block_id)
    block_key = get_object_or_404(BlockKey, block=block, target_alias=my_identity.alias)

    decrypted_data = read_block_data(block, block_key, my_identity)

    response = HttpResponse(decrypted_data.decode("utf-8"))
    response["content-type"] = "text/plain"

    return response
    

@require_http_methods(["GET"])    
def query_blocks(request: HttpRequest):
    from_ts = request.GET["from_ts"]
    alias = request.GET["alias"]
    
    if isinstance(from_ts, list):
        return HttpResponseBadRequest("from_ts can be provided only once")
    if isinstance(alias, list):
        return HttpResponseBadRequest("alias can be provided only once")

    try:
        requesting_identity = Identities.objects.get(alias=alias)
        from_ts = int(from_ts)

        process_query(requesting_identity, from_ts)
        return JsonResponse({"message": "query accepted"})
    except Identities.DoesNotExist:
        return HttpResponseBadRequest("unknown alias, run discover first")
    


@csrf_exempt
@require_http_methods(["POST"])
def push_block(request):
    data = json.loads(request.body)
    try:
        jsc.validate(data, {
            "type": "object",
            "properties": {
                "block": {
                    "type": "object",
                },
                "block_keys": {
                    "type": "array",
                    "items": {
                        "type": "object",
                    },
                    "minItems": 1,
                },
                "block_attributes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                    }
                },
                "call_stack": {
                    "type": "number"
                }
            },
            "required": ["block", "block_keys", "call_stack", "block_attributes"]
        }) 

        block = Block(**data["block"])
        block_keys = [BlockKey(block=block, encrypted_key=x["encrypted_key"], target_alias=x["target_alias"]) for x in data["block_keys"]]
        block_attributes = [BlockAttribute(block=block, key=x['key'], value=x["value"]) for x in data["block_attributes"]]

        try:
            Block.objects.filter(block_id=block.block_id).get()
            logger.info(f"block/{block.block_id} already exists")
        except Block.DoesNotExist:
            if block.prev_block_id is not None:
                try:
                    Block.objects.filter(block_id=block.prev_block_id)
                    
                except Block.DoesNotExist:
                    logger.info(f"block/{block.prev_block_id} is missing")
                    return HttpResponseBadRequest("missing prev block")
            
            block = validate_block(block, block_keys)
            save_block(block, block_keys, block_attributes)

            publish_block(block, block_keys, block_attributes, data["call_stack"])

        return HttpResponse("ok")
        
    except jsc.ValidationError as e:
        return HttpResponseBadRequest(e.message)
    except BlockValidationFailedException:
        return HttpResponseBadRequest("block validation failed")
