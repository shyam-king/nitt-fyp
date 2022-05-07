from django.contrib import admin

import blockchain.models as m

class BlockAdmin(admin.ModelAdmin):
    ordering = ['-timestamp']

# Register your models here.
admin.site.register(m.Block, BlockAdmin)
admin.site.register(m.BlockKey)
admin.site.register(m.BlockAttribute)
admin.site.register(m.BlockMessage)
