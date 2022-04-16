from django.contrib import admin

from blockchain.models import Block, BlockKey

# Register your models here.
admin.site.register(Block)
admin.site.register(BlockKey)
