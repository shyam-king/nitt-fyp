from dataclasses import field
from django.db import models

class Block(models.Model):
    block_id = models.CharField(max_length=255, primary_key=True)
    block_data = models.TextField(null=False)
    timestamp = models.BigIntegerField(null=False)
    block_type = models.CharField(max_length=255, null=False)
    source = models.CharField(max_length=255, null=False)
    signature = models.TextField(null=False)
    self_verified = models.BooleanField(default=False)
    verification_timestamp = models.BigIntegerField(null=True)
    aes_nonce=models.TextField(null=False)
    aes_auth_tag=models.TextField(null=False)
    prev_block_id=models.CharField(max_length=255, null=True)
    prev_block_hash=models.TextField(null=True)

    def __str__(self) -> str:
        return f"{self.block_type}/{self.block_id}"

class BlockKey(models.Model):
    block = models.ForeignKey(Block, on_delete=models.CASCADE)
    encrypted_key = models.TextField(null=False)
    target_alias = models.CharField(max_length=255, null=False)

    def __str__(self) -> str:
        return f"{self.block_id}/key/{self.target_alias}"
        
class BlockAttribute(models.Model):
    block = models.ForeignKey(Block, on_delete=models.CASCADE)
    key = models.CharField(max_length=255, null=False)
    value = models.CharField(max_length=255, null=False)

    def __str__(self) -> str:
        return f"{self.block} / {self.key} = {self.value}"

class BlockTypes:
    GENESIS_BLOCK = "genesis"
    NEW_AUCTION = "new_auction"
    PARTICIPATE_IN_AUCTION = "participate_in_auction"
    AUCTION_STATE_CHANGE = "auction_state_change"
    SUBMITTED_BID = "submitted_bid"
    MATCHED_BID_RESULT = "matched_bid_result"
    MCP_EVALUATED = "mcp_evaluated"
