from django.contrib import admin

import blockchain.models as m

# Register your models here.
admin.site.register(m.Block)
admin.site.register(m.BlockKey)
admin.site.register(m.BlockAttribute)
admin.site.register(m.BlockMessage)
