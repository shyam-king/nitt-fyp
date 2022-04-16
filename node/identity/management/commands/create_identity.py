from django.core.management.base import BaseCommand, CommandError

from identity.models import Identities
import os
import uuid
import rsa
import base64

class Command(BaseCommand):
    help = 'My identity for the current node'

    def handle(self, *args, **kwargs):
        try:
            try:
                my_identity = Identities.objects.get(is_self=True)
                print(f"identity already exists: {my_identity.alias}")
            except Identities.DoesNotExist:
                (pubkey, privkey) = rsa.newkeys(512)
                pubkey_bytes = pubkey.save_pkcs1()
                pubkey_b64 = base64.encodebytes(pubkey_bytes)
                privkey_bytes = privkey.save_pkcs1()
                privkey_b64 = base64.encodebytes(privkey_bytes)

                my_alias = str(uuid.uuid4())

                my_identity = Identities(
                    uri = os.getenv("NODE_URI", "http://localhost:8000"),
                    alias = my_alias,
                    pub_key = pubkey_b64.decode("ascii"),
                    private_key = privkey_b64.decode("ascii"),
                    is_self = True,
                    source = my_alias
                )
                my_identity.save()
                print(f"created identity with alias {my_alias}")
                pass
        except Exception as e:
            print(e)
            raise CommandError('Initalization failed.')

