from functools import wraps
from django.http import HttpResponseForbidden
import os
from .identity import is_genesis_node

def genesis_only(function):
  @wraps(function)
  def wrap(request, *args, **kwargs):
        if is_genesis_node():
             return function(request, *args, **kwargs)
        else:
            return HttpResponseForbidden("not genesis")
  return wrap
  