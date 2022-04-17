from xml.dom.minidom import Identified
from django.contrib import admin

# Register your models here.
from .models import Identities

admin.site.register(Identities)
