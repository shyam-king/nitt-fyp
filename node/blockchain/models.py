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

    def get_dict(self):
        return {
            "block_id": self.block_id,
            "block_type": self.block_type,
            "block_data": self.block_data,
            "timestamp": self.timestamp,
            "source": self.source,
            "signature": self.signature,
            "aes_nonce": self.aes_nonce,
            "aes_auth_tag": self.aes_auth_tag,
            "prev_block_id": self.prev_block_id,
            "prev_block_hash": self.prev_block_hash
        }

class BlockKey(models.Model):
    block = models.ForeignKey(Block, on_delete=models.CASCADE)
    encrypted_key = models.TextField(null=False)
    target_alias = models.CharField(max_length=255, null=False)

    def __str__(self) -> str:
        return f"{self.block_id}/key/{self.target_alias}"

    def get_dict(self):
        return {
            "encrypted_key": self.encrypted_key,
            "target_alias": self.target_alias,
        };
