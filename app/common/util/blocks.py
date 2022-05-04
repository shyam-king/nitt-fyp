import base64
from uuid import uuid4

from django.urls import reverse
from blockchain.models import Block, BlockKey, BlockAttribute
from identity.models import Identities
import rsa
import os
import hashlib

from common.events import handle_post_block_validation
from .rsa import load_rsa_public_key

from .aes import encrypt_AES_GCM, decrypt_AES_GCM
import time

from django.forms.models import model_to_dict

import requests
from furl import furl
import traceback

import logging
logger = logging.getLogger(__name__)

from concurrent.futures import ThreadPoolExecutor
pool = ThreadPoolExecutor(max_workers=4)


class BlockValidationFailedException(Exception):
    def __init__(self, block_id):
        super().__init__(f"validation failed for block {block_id}")


def create_new_block(
    data: bytes,
    block_type: str,
    attributes: dict,
    identity: Identities,
    target_identites: list,
    prev_block = None
) -> tuple[Block, list[BlockKey], list[BlockAttribute]]:
    block_id = str(uuid4())

    privatekey_bytes = base64.decodebytes(identity.private_key.encode("ascii"))
    privatekey = rsa.PrivateKey.load_pkcs1(privatekey_bytes)

    aes_key = os.urandom(32)

    encrypted_data, aes_nonce, aes_auth_code = encrypt_AES_GCM(data, aes_key)
    encrypted_data_b64 = base64.encodebytes(encrypted_data).decode("ascii")
    aes_nonce_b64 = base64.encodebytes(aes_nonce).decode("ascii")
    aes_auth_code_b64 = base64.encodebytes(aes_auth_code).decode("ascii")

    signature = rsa.sign(encrypted_data, privatekey, "SHA-256")
    signature_b64 = base64.encodebytes(signature).decode("ascii")

    prev_block_id = None 
    prev_block_hash = None

    if prev_block is not None:
        prev_block_id = prev_block.block_id

        m = hashlib.sha256()
        m.update(base64.decodebytes(prev_block.block_data.encode("ascii")))
        m.update(prev_block.source.encode("ascii"))
        
        prev_block_hash = base64.encodebytes(m.digest()).decode("ascii")

    block = Block(
        block_id = block_id,
        block_data = encrypted_data_b64,
        timestamp = int(time.time()),
        block_type = block_type,
        source = identity.alias,
        signature = signature_b64,
        aes_nonce = aes_nonce_b64,
        aes_auth_tag = aes_auth_code_b64,
        prev_block_id = prev_block_id,
        prev_block_hash = prev_block_hash
    )

    block_keys = []

    for target in target_identites:
        pubkey_bytes = base64.decodebytes(target.pub_key.encode("ascii"))
        pubkey = rsa.PublicKey.load_pkcs1(pubkey_bytes)

        encrypted_key = rsa.encrypt(aes_key, pubkey)
        encrypted_key_b64 = base64.encodebytes(encrypted_key).decode("ascii")

        block_keys.append(
            BlockKey(
                block = block,
                encrypted_key = encrypted_key_b64,
                target_alias = target.alias
            )
        )

    block_attributes = []
    for k in attributes.keys():
        block_attributes.append(BlockAttribute(
            block = block,
            key=k,
            value=attributes[k]
        ))


    return block, block_keys, block_attributes


def read_block_data(block: Block, block_key: BlockKey, identity: Identities | None = None):
    if identity is None:
        identity = Identities.objects.filter(alias=block_key.target_alias).get()

    encrypted_data_b64 = block.block_data
    encrypted_data = base64.decodebytes(encrypted_data_b64.encode("ascii"))
    
    encrypted_key_b64 = block_key.encrypted_key
    encrypted_key = base64.decodebytes(encrypted_key_b64.encode("ascii"))

    private_key_b64 = identity.private_key
    private_key = rsa.PrivateKey.load_pkcs1(base64.decodebytes(private_key_b64.encode("ascii")))

    aes_key = rsa.decrypt(encrypted_key, private_key)
    aes_nonce = base64.decodebytes(block.aes_nonce.encode("ascii"))
    aes_auth_tag = base64.decodebytes(block.aes_auth_tag.encode("ascii"))

    decrypted_data = decrypt_AES_GCM((encrypted_data, aes_nonce, aes_auth_tag), aes_key)
    return decrypted_data


def publish_block(block: Block, block_keys: list[BlockKey], block_attributes: list[BlockAttribute], call_stack = 0, from_source = None):
    logger.info(f"adding block {block.block_id} to publishing thread")
    pool.submit(__publish_block, block, block_keys, block_attributes, call_stack, from_source)


def __publish_block(block: Block, block_keys: list, block_attributes: list, call_stack = 0, from_source = None):
    try:
        if call_stack == 3:
            logger.info(f"skipping further publish of block {block.block_id} since call_stack has reached 3")
            return 
        
        data = {
            "block": model_to_dict(block),
            "block_keys": [model_to_dict(k) for k in block_keys],
            "block_attributes": [model_to_dict(k) for k in block_attributes],
            "call_stack": call_stack + 1
        }

        identities = Identities.objects.exclude(is_self=True).exclude(source=from_source).all()
        for identity in identities:
            logger.info(f"pushing block {block.block_id} to {identity.alias}")
            idenitity_url = furl(identity.uri)
            idenitity_url.path = reverse("push_block")
            response = requests.post(idenitity_url.tostr(), headers={
                "content-type": "application/json",
            }, json = data)
            
            if response.status_code != 200:
                logger.warning(f"pushing block to {identity.alias} failed with status code {response.status_code}:")
                logger.warning(response.text)

    except Exception as e:
        logger.error(f"error publishing block/{block.block_id}:")
        logger.error("".join(traceback.format_exception(e)))



def process_query(requesting_identity, from_ts):
    logger.info(f"adding query {requesting_identity.alias}/{from_ts} to pool")
    pool.submit(__process_query, requesting_identity, from_ts)

def __process_query(requesting_identity, from_ts):
    logger.info(f"processing query for {requesting_identity.alias} with from_ts={from_ts}")

    blocks = Block.objects.filter(timestamp__gt=from_ts)
    for block in blocks:
        pool.submit(__push_block, requesting_identity, block) 

def __push_block(identity, block):
    logger.info(f"pushing block/{block.block_id} to {identity.alias}")
    block_keys = BlockKey.objects.filter(block=block)
    block_attr = BlockAttribute.objects.filter(block=block)

    params = {
        "block": model_to_dict(block),
        "block_keys": [model_to_dict(k) for k in block_keys],
        "block_attributes": [model_to_dict(a) for a in block_attr],
        "call_stack": 0
    }

    uri = furl(identity.uri)
    uri.path = reverse("push_block")
    
    response = requests.post(uri, headers={
        "content-type": "application/json",
    }, json=params)

    if response.status_code != 200:
        logger.warn(f"push_block api returned with status_code={response.status_code}")
        logger.warn(response.text)

def __check_if_block_is_valid(block: Block):
    try:
        identity = Identities.objects.get(alias=block.source)
        block_data = base64.decodebytes(block.block_data.encode("ascii"))
        signature = base64.decodebytes(block.signature.encode("ascii"))
        public_key = load_rsa_public_key(identity.pub_key)

        rsa.verify(block_data, signature, public_key)

    except Identities.DoesNotExist:
        return False
    except rsa.VerificationError:
        raise BlockValidationFailedException(block.block_id)
    return True


def save_block(block: Block, block_keys: list[BlockKey], block_attributes: list[BlockAttribute]):
    existing_block = Block.objects.filter(block_id=block.block_id).count() > 0
    if not existing_block:
        block.save()
        for key in block_keys:
            key.save()
        for attr in block_attributes:
            attr.save()


def validate_block(block: Block, block_keys: list[BlockKey]):
    if __check_if_block_is_valid(block):
        block.self_verified = True 
        block.verification_timestamp = int(time.time())

        handle_post_block_validation(block, block_keys)
    else:
        block.self_verified = False 
        block.verification_timestamp = None 

    return block

def get_latest_block():
    latest_block = Block.objects.order_by('-timestamp').all()[0]
    return latest_block
