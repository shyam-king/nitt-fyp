import base64
from uuid import uuid4

from django.urls import reverse
from blockchain.models import BlockMessage
from blockchain.models import Block, BlockKey, BlockAttribute, BlockMessage
from identity.models import Identities
import rsa
import os
import hashlib

from common.events import handle_post_block_commit
from common.util.identity import get_my_identity

from .rsa import load_rsa_private_key, load_rsa_public_key

from .aes import encrypt_AES_GCM, decrypt_AES_GCM
import time

from django.forms.models import model_to_dict

import requests
from furl import furl
import traceback

import logging
logger = logging.getLogger(__name__)

from concurrent.futures import ThreadPoolExecutor
pool = ThreadPoolExecutor(max_workers=5)

def generate_message_signature(block_id, message):
    identity = get_my_identity()

    hasher = hashlib.sha256()
    
    hasher.update(identity.alias.encode("utf-8"))
    hasher.update(block_id.encode("utf-8"))
    hasher.update(message.encode("utf-8"))
    
    hashed_data = hasher.digest()

    private_key = load_rsa_private_key(identity.private_key)

    signature = rsa.sign(hashed_data, private_key, 'SHA-256')

    return base64.encodebytes(signature).decode("ascii")

def verify_message_signature(source: str, block_id: str, message: str, signature: str):
    identity = Identities.objects.filter(alias=source).get()

    hasher = hashlib.sha256()
    hasher.update(source.encode("utf-8"))
    hasher.update(block_id.encode("utf-8"))
    hasher.update(message.encode("utf-8"))
    hashed_data = hasher.digest()

    signature = base64.decodebytes(signature.encode("ascii"))

    public_key = load_rsa_public_key(identity.pub_key)

    try:
        rsa.verify(hashed_data, signature, public_key)
    except rsa.VerificationError:
        return False

    return True

def handle_post_block_message(block_message):
    pool.submit(__handle_post_block_message, block_message) 

def __handle_post_block_message(block_message: BlockMessage):
    try:
        logger.info(f"handling post block message for {block_message.block}/{block_message.message_type}")
        block = block_message.block

        if block_message.message_type == BlockMessage.Types.PrePrepare:
            logger.debug(f"{block}/PrePrepare post processing")
            if validate_block(block):
                send_block_message(block.block_id, BlockMessage.Types.Prepare)
            else:
                logger.warn(f"block/{block.block_id} is being rejected due to validation failure")
        elif block_message.message_type == BlockMessage.Types.Prepare:
            logger.debug(f"{block}/Prepare post processing")
            successful_preprepare_messages = BlockMessage.objects.filter(block=block, message_type=BlockMessage.Types.Prepare, verified_signature=True).count()
            total_nodes = Identities.objects.count()

            if successful_preprepare_messages > 2 * (total_nodes-1)/3 + 1:
                send_block_message(block.block_id, BlockMessage.Types.Commit)
        elif block_message.message_type == BlockMessage.Types.Commit:
            logger.debug(f"{block}/Commit post processing")
            successful_commit_messages = BlockMessage.objects.filter(block=block, message_type=BlockMessage.Types.Commit, verified_signature=True).count()
            total_nodes = Identities.objects.count()

            if successful_commit_messages > 2 * (total_nodes-1)/3 + 1:
                if not block.is_committed:
                    block.is_committed = True 
                    block.save()
                    handle_post_block_commit(block)
    except Exception as e:
        logger.error(f"error post processing of {block}/{block_message.message_type}")
        logger.error("".join(traceback.format_exception(e)))

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


def publish_block(block: Block, block_keys: list[BlockKey], block_attributes: list[BlockAttribute]):
    logger.info(f"adding block {block.block_id} to publishing thread")
    pool.submit(__publish_block, block, block_keys, block_attributes)


def send_block_message(block_id, message):
    try:
        logger.info(f"sending block/{block_id}/{message} message")
        identity = get_my_identity()
        source = identity.alias 

        signature = generate_message_signature(block_id, message)

        data = {
            "block_id": block_id,
            "source": source,
            "signature": signature,
            "message": message
        }

        for node in Identities.objects.all():
            uri = furl(node.uri)
            uri.path = reverse("send_block_message")

            logger.info(f"sending {block_id}/{message} to {uri}")

            request = requests.post(uri.tostr(), headers={
                "content-type": "application/json",
            }, json=data)

            if request.status_code != 200:
                logger.error(f"error sending {block_id}/{message} to {node.alias}:")
                logger.error(request.text)
    except Exception as e:
        logger.error(f"error sending message for block/{block_id}/{message}:")
        logger.error("".join(traceback.format_exception(e)))


def __publish_block(block: Block, block_keys: list[BlockKey], block_attributes: list[BlockAttribute]):
    try:
        logger.info(f"publishing block/{block.block_id}")
        data = {
            "block": model_to_dict(block),
            "block_keys": [model_to_dict(k) for k in block_keys],
            "block_attributes": [model_to_dict(k) for k in block_attributes]
        }

        identities = Identities.objects.all()
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

        pool.submit(send_block_message, block.block_id, BlockMessage.Types.PrePrepare)

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
    ## fix this
    return True
    ##

    logger.debug(f"verifying block/{block.block_id}")
    try:
        logger.debug(f"checking for branching issues in {block}")
        prev_block = Block.objects.filter(prev_block_id=block.prev_block_id, timestamp__lte=block.timestamp, block_id__ne=block.block_id).count()
        if prev_block > 0:
            logger.debug(f"rejecting {block} due to branching")
            return False

        logger.debug(f"verifying signature in {block}")
        identity = Identities.objects.filter(alias=block.source).get()
        block_data = base64.decodebytes(block.block_data.encode("ascii"))
        signature = base64.decodebytes(block.signature.encode("ascii"))
        public_key = load_rsa_public_key(identity.pub_key)

        rsa.verify(block_data, signature, public_key)
    except rsa.VerificationError:
        logger.debug(f"rejecting {block} due to signature mismatch")
        return False
    except Exception as e:
        logger.error(f"error in block validation: {e}")
        logger.error("".join(traceback.format_exception(e)))
        raise e

    return True


def save_block(block: Block, block_keys: list[BlockKey], block_attributes: list[BlockAttribute]):
    existing_block = Block.objects.filter(block_id=block.block_id).count() > 0
    if not existing_block:
        block.save()
        for key in block_keys:
            key.save()
        for attr in block_attributes:
            attr.save()

def validate_block(block: Block):
    return __check_if_block_is_valid(block)

def get_latest_block():
    latest_block = Block.objects.order_by('-timestamp').all()[0]
    return latest_block
