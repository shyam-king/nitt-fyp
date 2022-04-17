import base64
import rsa

def load_rsa_private_key(b64_key: str):
    return rsa.PrivateKey.load_pkcs1(base64.decodebytes(b64_key.encode("ascii")))

def load_rsa_public_key(b64_key: str):
    return rsa.PublicKey.load_pkcs1(base64.decodebytes(b64_key.encode("ascii")))
