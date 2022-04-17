from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
import os

class Command(BaseCommand):
    help = 'Creates admin user'

    def handle(self, *args, **kwargs):
        try:
            usr = User.objects.get(username="admin")
            print("admin user already initialized")
        except User.DoesNotExist:
            usr = User(username="admin")
            usr.set_password(os.getenv("NODE_ADMIN_PASSWORD", "password"))
            usr.is_superuser = True
            usr.save()
            print("admin user created")
        except:
            raise CommandError('Initalization failed.')

