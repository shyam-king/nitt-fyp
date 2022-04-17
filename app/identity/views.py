from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseServerError
import json
from django.views.decorators.http import require_http_methods
import jsonschema as jsc
import rsa
from common.util.identity import sign_test_string, get_my_identity, CouldNotVerifyIdentityException, validate_identity
from identity.models import Identities
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
@require_http_methods(["POST"])
def invalidate(request):
    data = json.loads(request.body)
    try:    
        jsc.validate(data, {
            "type": "object",
            "properties": {
                "testString": {"type": "string"}
            },
            "required": ["testString"]
        })

        teststring = data["testString"]

        signature = sign_test_string(teststring, get_my_identity())

        return JsonResponse({"signature": signature})
    except jsc.ValidationError as e:
        return HttpResponseBadRequest(e.message) 

@csrf_exempt
@require_http_methods(["POST"])
def discover(request):
    data = json.loads(request.body)
    
    try:    
        jsc.validate(data, {
            "type": "object",
            "properties": {
                "identity": {
                    "type": "object",
                    "properties": {
                        "alias": {"type": "string"},
                        "publicKey": {"type": "string"},
                        "uri": {"type": "string"}
                    },
                    "required": ["alias", "publicKey", "uri"],
                },
            },
            "required": ["identity"]
        })

        identity = data["identity"]
        validate_identity(identity["alias"], identity["publicKey"], identity["uri"])

        existing_identity, _ = Identities.objects.get_or_create(
            alias=identity["alias"],
            pub_key = identity["publicKey"],
            uri = identity["uri"],
            is_self = False,
            source = identity["alias"]
        )

        identities = Identities.objects.exclude(alias=existing_identity.alias)
        identities = [{"alias": i.alias, "publicKey": i.pub_key, "uri": i.uri} for i in identities]
        
        my_identity = get_my_identity()

        return JsonResponse({"identities": identities, "source": my_identity.alias}) 

    except jsc.ValidationError as e:
        return HttpResponseBadRequest(e.message)
    except CouldNotVerifyIdentityException:
        return HttpResponseServerError("error while verifying identity")
    except rsa.VerificationError:
        return HttpResponseBadRequest("could not verify identity")

