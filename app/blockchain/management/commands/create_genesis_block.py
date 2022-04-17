from django.core.management.base import BaseCommand, CommandError
from identity.models import Identities

from common.util.blocks import create_new_block

import logging
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Creates the genesis block'

    def handle(self, *args, **kwargs):
        logger.info("Checking identity...")
        try:
            my_identity = Identities.objects.get(is_self=True)
        except Identities.DoesNotExist:
            logger.error("identity not found, run create_idenitity first")
            raise CommandError("identity could not be found for this node")
        
        logger.info("creating genesis block")
        block, keys, attributes = create_new_block(b'genesis', 'genesis', {}, my_identity, [my_identity])

        block.save()
        for key in keys:
            key.save()

        for attr in attributes:
            attr.save()
        
        logger.info("created")

