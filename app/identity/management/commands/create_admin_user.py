from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
import os

import logging
logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Creates admin user'

    def handle(self, *args, **kwargs):
        try:
            usr = User.objects.get(username="admin")
            logger.info("admin user already initialized")
        except User.DoesNotExist:
            usr = User.objects.create_user(username="admin", password=os.getenv("NODE_ADMIN_PASSWORD", "password"), email="admin@example.com")
            usr.is_superuser = True
            usr.save()
            logger.info("admin user created")
        except:
            raise CommandError('Initalization failed.')

