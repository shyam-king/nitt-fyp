from django.core.management.base import BaseCommand, CommandError
from identity.models import Identities

from common.util.blocks import create_new_block

class Command(BaseCommand):
    help = 'Creates the genesis block'

    def handle(self, *args, **kwargs):
        self.stdout.write("Checking identity...")
        try:
            my_identity = Identities.objects.get(is_self=True)
        except Identities.DoesNotExist:
            self.stderr.write("identity not found, run create_idenitity first")
            raise CommandError("identity could not be found for this node")
        
        self.stdout.write("creating genesis block")
        block, keys = create_new_block(b'genesis', 'genesis', my_identity, [my_identity])

        block.save()
        for key in keys:
            key.save()
        
        self.stdout.write("created")

