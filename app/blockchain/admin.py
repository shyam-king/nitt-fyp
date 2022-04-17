from django.contrib import admin

from blockchain.models import Block, BlockKey, BlockAttribute

# Register your models here.
admin.site.register(Block)
admin.site.register(BlockKey)
admin.site.register(BlockAttribute)
