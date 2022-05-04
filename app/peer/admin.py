from django.contrib import admin
from .models import Auction, AuctionParticipant

# Register your models here.
admin.site.register(Auction)
admin.site.register(AuctionParticipant)
