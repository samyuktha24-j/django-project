from django.shortcuts import render
from django.http import JsonResponse
import hashlib
from base64 import b64encode
import hmac

SECRET_KEY = b"csms-secret-key"

# Pages
def lms_home(request):
    return render(request, 'lms/home.html')

def course_detail(request):
    return render(request, 'lms/course_detail.html')

# Hash
def generate_hash(request):
    text = request.POST.get("text", "")
    return JsonResponse({"hash": hashlib.sha256(text.encode()).hexdigest()})

# Encrypt
def encrypt_text(request):
    text = request.POST.get("text", "")
    return JsonResponse({"encrypted": b64encode(text.encode()).decode()})

# Sign
def sign_text(request):
    text = request.POST.get("text", "")
    sig = hmac.new(SECRET_KEY, text.encode(), hashlib.sha256).hexdigest()
    return JsonResponse({"signature": sig})

# Verify
def verify_signature(request):
    text = request.POST.get("text", "")
    sig = request.POST.get("signature", "")
    valid = sig == hmac.new(SECRET_KEY, text.encode(), hashlib.sha256).hexdigest()
    return JsonResponse({"valid": valid})

# ✅ Progress button (SAFE VERSION)
def mark_complete(request):
    return JsonResponse({"status": "completed"})

def owasp_page(request):
    return render(request, 'lms/owasp.html')

def learning_dashboard(request):
    return render(request, "lms/learning.html")

import random, hashlib
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json

# ================= GENERATE SEED =================
def generate_seed(request):
    proprietary = request.GET.get("proprietary", "default")

    seed = hex(random.getrandbits(32))[2:]
    return JsonResponse({"seed": seed})


# ================= PROCESS SEED =================
@csrf_exempt
def process_seed(request):
    data = json.loads(request.body)

    seed = data.get("seed")
    proprietary = data.get("proprietary")

    # Fake proprietary logic
    key = hashlib.sha256((seed + proprietary).encode()).hexdigest()[:16]
    encrypted = hashlib.md5((seed + key).encode()).hexdigest()
    hash_val = hashlib.sha256(encrypted.encode()).hexdigest()

    return JsonResponse({
        "key": key,
        "encrypted": encrypted,
        "hash": hash_val
    })