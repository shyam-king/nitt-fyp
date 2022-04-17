from uuid import uuid4
from django.urls import reverse
import requests
from identity.models import Identities
import base64
import rsa

from identity.models import Identities
from .rsa import load_rsa_private_key, load_rsa_public_key

import logging
logger = logging.getLogger(__name__)

from furl import furl
from concurrent.futures import ThreadPoolExecutor

pool = ThreadPoolExecutor(max_workers=5)

class CouldNotVerifyIdentityException(Exception):
    def __init__(self, alias) -> None:
        super().__init__(f"some error occured while verifying identity {alias}")

def validate_identity(alias, public_key, uri):
    logger.info(f"invalidating identity of {alias} at {uri}")
    invalidation_url = furl(uri)
    invalidation_url.path = reverse("invalidate_identity")

    teststring = str(uuid4())

    response = requests.post(invalidation_url.tostr(), headers={
        "content-type": "application/json",
    }, json={
        "testString": teststring,
    })

    if response.status_code != 200:
        logger.warn(f"invalidation API returned error for {alias} at {uri}, status_code: {response.status_code}")
        logger.warn(response.text)
        raise CouldNotVerifyIdentityException(alias)
        
    verify_signed_test_string(teststring, public_key, response.json()["signature"])

def get_my_identity():
    return Identities.objects.get(is_self=True)

def sign_test_string(test_string: str, identity: Identities):
    private_key = load_rsa_private_key(identity.private_key)
    signature = rsa.sign(test_string.encode("utf-8"), private_key, "SHA-256")
    return base64.encodebytes(signature).decode("ascii")

def verify_signed_test_string(test_string: str, public_key_b64: str, given_signature_b64: str):
    public_key = load_rsa_public_key(public_key_b64)
    signature = base64.decodebytes(given_signature_b64.encode("ascii"))
    rsa.verify(test_string.encode("utf-8"), signature, public_key)


def verify_and_add_identity(alias, pub_key, uri, source):
    pool.submit(__verify_and_add_identity, alias, pub_key, uri, source)


def __verify_and_add_identity(alias, pub_key, uri, source):
    try:
        existing_identity = Identities.objects.get(alias=alias)
    except Identities.DoesNotExist:
        logger.info(f"discovered identity {alias} from {source}, verifying...")
        
        try:
            validate_identity(alias, pub_key, uri)
            Identities.objects.get_or_create(
                alias=alias,
                pub_key = pub_key,
                uri = uri,
                is_self = False,
                source = source
            )
        except rsa.VerificationError:
            logger.info("verification failed for identity {alias}")
        except CouldNotVerifyIdentityException:
            logger.info("error occured while verifying identity {alias}")


