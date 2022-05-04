from django.shortcuts import render

from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods 

from django.http import HttpResponse, JsonResponse

from common.events import register_event_handler
from common.events import auction_events

from blockchain.models import BlockTypes



# event handlers
register_event_handler(BlockTypes.NEW_AUCTION, auction_events.new_auction_event)
