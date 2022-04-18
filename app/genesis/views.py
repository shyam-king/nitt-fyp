from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from common.util.decorators import genesis_only

@csrf_exempt
@require_http_methods(["POST"])
@genesis_only
def ping(request):
    return JsonResponse({"message": "ok"})


