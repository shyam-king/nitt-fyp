from django.http import HttpResponse, HttpResponseBadRequest
from blockchain.models import Block, BlockKey, BlockAttribute
from identity.models import Identities
from django.shortcuts import get_object_or_404
from common.util.blocks import read_block_data, publish_block, BlockValidationFailedException, validate_block
from django.views.decorators.http import require_http_methods
import jsonschema as jsc
import json
import time


@require_http_methods(["GET"])
def view_block(request, block_id):
    my_identity = get_object_or_404(Identities, is_self=True)
    block = get_object_or_404(Block, pk=block_id)
    block_key = get_object_or_404(BlockKey, block=block, target_alias=my_identity.alias)

    decrypted_data = read_block_data(block, block_key, my_identity)

    response = HttpResponse(decrypted_data.decode("utf-8"))
    response["content-type"] = "text/plain"

    return response
    

@require_http_methods(["POST"])
def push_block(request):
    data = json.loads(request.data)
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
            "required": ["block", "block_keys", "call_stack"]
        }) 

        block = Block(*data["block"])
        block = validate_block(block)
        
        block.self_verified = True 
        block.verification_timestamp = int(time.time())

        block_keys = [BlockKey(*x) for x in data["block_keys"]]
        block_attributes = [BlockAttribute(*x) for x in data["block_attributes"]]

        existing_block = len(Block.objects.filter(block_id=block.block_id)) > 0
        if not existing_block:
            block.save()
            for key in block_keys:
                key.save()
            for attr in block_attributes:
                attr.save()

        publish_block(block, block_keys, data["call_stack"])

        return HttpResponse("ok")
        
    except jsc.ValidationError as e:
        return HttpResponseBadRequest(e.message)
    except BlockValidationFailedException:
        return HttpResponseBadRequest("block validation failed")
