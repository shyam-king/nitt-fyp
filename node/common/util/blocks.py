import base64
from uuid import uuid4
from blockchain.models import Block, BlockKey
from identity.models import Identities
import rsa
import os

from .aes import encrypt_AES_GCM, decrypt_AES_GCM
import time

def create_new_block(
    data: bytes,
    block_type: str,
    identity: Identities,
    target_identites: list,
):
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

    block = Block(
        block_id = block_id,
        block_data = encrypted_data_b64,
        timestamp = int(time.time()),
        block_type = block_type,
        source = identity.alias,
        signature = signature_b64,
        aes_nonce = aes_nonce_b64,
        aes_auth_tag = aes_auth_code_b64
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

    return block, block_keys
