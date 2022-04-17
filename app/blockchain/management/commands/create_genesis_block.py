from django.core.management.base import BaseCommand, CommandError
from blockchain.models import Block
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

        logger.info("checking if genesis block already present")
        try:
            existing_block = Block.objects.get(block_type="genesis")
            logging.info(f"genesis block already exists: {existing_block.block_id}")
        except Block.DoesNotExist: 
            logger.info("creating genesis block")
            block, keys, attributes = create_new_block(b'genesis', 'genesis', {}, my_identity, [my_identity])

            block.save()
            for key in keys:
                key.save()

            for attr in attributes:
                attr.save()
            
            logger.info(f"created genesis block {block.block_id}")

