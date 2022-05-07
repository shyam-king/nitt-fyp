import logging
import os
from django.urls import reverse
from common.util.identity import get_my_identity
from blockchain.models import Block
from identity.models import Identities
from django.db.models import Max
import requests
from furl import furl
import random

logger = logging.getLogger(__name__)

def job():
    logger.info("syncing blocks")

    my_identity = get_my_identity()
    from_ts = Block.objects.all().aggregate(from_ts=Max('timestamp'))["from_ts"]
    if from_ts is None:
        from_ts = 0

    uris = []
    if os.getenv("IS_GENESIS_NODE", "false") != "true":
        genesis_uri = os.getenv("GENESIS_URI")
        if genesis_uri is None:
            logger.error(f"cannot sync blocks because genesis URI not configured.")
            return 
        uris.append(genesis_uri)

    other_identities = Identities.objects.exclude(alias=my_identity.alias).all()
    for identity in other_identities:
        uris.append(identity.uri)
    

    uri = furl(random.choice(uris))

    logger.info(f"syncing blocks with {uri.tostr()}")

    uri.path = reverse("query_blocks")

    response = requests.get(uri, params={
        "alias": my_identity.alias,
        "from_ts": from_ts
    })

    if response.status_code != 200:
        logger.warn(f"query_blocks api returned status_code={response.status_code}")
        logger.warn(response.text)
    
    
