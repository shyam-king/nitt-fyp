import logging

from django.urls import reverse
logger = logging.getLogger(__name__)

from common.util.identity import get_my_identity, verify_and_add_identity
from furl import furl

import requests

import os

def job():
    if os.getenv("IS_GENESIS_NODE", "false") == "true":
        logger.info("skipping identity sync")
        return

    logger.info("syncing identities with genesis")
    my_identity = get_my_identity()
    genesis_uri = os.getenv("GENESIS_URI")
    if genesis_uri is None:
        logger.error(f"cannot sync identities because genesis URI not configured.")
        return 

    genesis_uri = furl(genesis_uri)
    discover_uri = genesis_uri
    discover_uri.path = reverse("discover_identity")

    response = requests.post(discover_uri.tostr(), headers={
        "content-type": "application/json",
    }, json={
        "identity": {
            "alias": my_identity.alias,
            "publicKey": my_identity.pub_key,
            "uri": my_identity.uri
        }
    })

    if response.status_code != 200:
        logger.error(f"discover_identity API returned error with status code: {response.status_code}")
        logger.error(response.text)
        return 
    
    data =  response.json()
    identities = data["identities"]
    for identity in identities:
        verify_and_add_identity(identity["alias"], identity["publicKey"], identity["uri"], data["source"])

