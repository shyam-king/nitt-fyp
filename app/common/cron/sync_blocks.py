import logging
import os
from django.urls import reverse
from common.util.identity import get_my_identity
from blockchain.models import Block
from django.db.models import Max
import requests
from furl import furl

logger = logging.getLogger(__name__)

def job():
    if os.getenv("IS_GENESIS_NODE", "false") == "true":
        logger.info("skipping block sync")
        return

    logger.info("syncing blocks with genesis")

    my_identity = get_my_identity()
    from_ts = Block.objects.all().aggregate(from_ts=Max('timestamp'))["from_ts"]
    if from_ts is None:
        from_ts = 0

    genesis_uri = os.getenv("GENESIS_URI")
    if genesis_uri is None:
        logger.error(f"cannot sync blocks because genesis URI not configured.")
        return 
    
    uri = furl(genesis_uri)
    uri.path = reverse("query_blocks")

    response = requests.get(uri, params={
        "alias": my_identity.alias,
        "from_ts": from_ts
    })

    if response.status_code != 200:
        logger.warn(f"query_blocks api returned status_code={response.status_code}")
        logger.warn(response.text)
    
    
