from django.db import models

# Create your models here.
class Identities(models.Model):
    uri = models.URLField()
    alias = models.CharField(max_length=256,primary_key=True)
    pub_key = models.TextField()
    private_key = models.TextField()
    is_self = models.BooleanField()
    source = models.CharField(max_length=256)

