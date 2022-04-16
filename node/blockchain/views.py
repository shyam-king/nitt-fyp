from django.http import HttpResponse
from django.shortcuts import render
from blockchain.models import Block, BlockKey
from identity.models import Identities
from django.shortcuts import get_object_or_404
from common.util.blocks import read_block_data


# Create your views here.
def view_block(request, block_id):
    my_identity = get_object_or_404(Identities, is_self=True)
    block = get_object_or_404(Block, pk=block_id)
    block_key = get_object_or_404(BlockKey, block=block, target_alias=my_identity.alias)

    decrypted_data = read_block_data(block, block_key, my_identity)

    return HttpResponse(decrypted_data.decode("utf-8"))
    
