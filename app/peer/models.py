from django.db import models

class Auction(models.Model):
    class States(models.TextChoices):
        CREATED = "CREATED"

        HOUR_AHEAD_BIDDING_STARTED = "HOUR_AHEAD_STARTED"
        HOUR_AHEAD_BIDDING_FINISHED = "HOUR_AHEAD_FINISHED"

        ADJUSTMENT_BIDDING_STARTED = "ADJUSTMENT_STARTED"
        ADJUSTMENT_BIDDING_FINISHED = "ADJUSTMENT_FINISHED"

        CANCELLED = "CANCELLED"
        COMPLETED = "COMPLETED"
        

    auction_id = models.CharField(max_length=255, primary_key=True)
    timestamp = models.BigIntegerField(null=False)
    status = models.CharField(max_length=255, choices=States.choices, default=States.CREATED)
    auction_leader = models.CharField(max_length=255, null=True)

    def __str__(self) -> str:
        return f"{self.auction_id}/{self.status}"
    

class AuctionParticipant(models.Model):
    auction = models.ForeignKey(Auction, on_delete=models.CASCADE)
    alias = models.CharField(max_length=255, null=False)
    node = models.IntegerField(null=True)
    pv_installment_factor = models.FloatField(null=True)

    def __str__(self) -> str:
        return f"{self.auction} / {self.alias} at node {self.node}"


class Bid(models.Model):
    class Types(models.TextChoices):
        HOUR_AHEAD = "HOUR_AHEAD"
        ADJUSTMENT = "ADJUSTMENT"

    auction = models.ForeignKey(Auction, on_delete=models.CASCADE)
    alias = models.CharField(max_length=255, null=False)
    bid_type = models.CharField(max_length=10, choices=Types.choices, default=Types.HOUR_AHEAD)
    units = models.FloatField(null=False)
    rate = models.FloatField(null=False)
    timestamp = models.BigIntegerField(null=False)
    
    def __str__(self) -> str:
        return f"{self.auction}/{self.bid_type} bid by {self.alias} of {self.units} units at {self.rate} rate"


class MCPResult(models.Model):
    auction = models.ForeignKey(Auction, on_delete=models.CASCADE)
    mcp = models.FloatField()

    def __str__(self) -> str:
        return f"{self.mcp} for auction => {self.auction}"


class BidMatch(models.Model):
    auction = models.ForeignKey(Auction, on_delete=models.CASCADE)
    alias = models.CharField(max_length=255)
    units = models.FloatField()

    def __str__(self) -> str:
        return f"{self.units} units for {self.alias} in {self.auction}"

class RiskAnalysisResult(models.Model):
    auction = models.ForeignKey(Auction, on_delete=models.CASCADE)
    alias = models.CharField(max_length=255)
    risky_units = models.FloatField()

    def __str__(self):
        if self.risky_units > 0:
            return f"{self.auction}/risky by {self.risky_units} units"
        return f"{self.auction}/not risky"
