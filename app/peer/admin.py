from django.contrib import admin
from .models import Auction, AuctionParticipant, Bid, BidMatch, MCPResult, RiskAnalysisResult

# Register your models here.
admin.site.register(Auction)
admin.site.register(AuctionParticipant)
admin.site.register(Bid)
admin.site.register(BidMatch)
admin.site.register(MCPResult)
admin.site.register(RiskAnalysisResult)
