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

    def __str__(self) -> str:
        return f"{self.auction_id}/{self.status}"
    
class AuctionParticipant(models.Model):
    auction = models.ForeignKey(Auction, on_delete=models.CASCADE)
    alias = models.CharField(max_length=255, null=False)
