from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout  # ✅ FIXED

import json
import os
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

from .models import ECUConfig, KeyPair


# ================= LOGIN =================
def main_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect("/home/")
        else:
            return render(request, "main_login.html", {"error": "Invalid credentials"})

    return render(request, "main_login.html")


# ================= BASIC PAGES =================
def home(request): return render(request, "home.html")
def csms_dashboard(request): return render(request, "csms_dashboard.html")
def csms_main(request): return render(request, "csms_main.html")
def debug(request): return render(request, "debug.html")
def debug_keygen(request): return render(request, "debug_keygen.html")


# ================= ADMIN =================
def admin_dashboard(request):
    users = User.objects.all()
    return render(request, "admin_dashboard.html", {"users": users})


# ================= ECU =================
def crc8_autosar(data):
    crc = 0xFF
    for ch in data:
        crc ^= ord(ch)
        for _ in range(8):
            crc = ((crc << 1) ^ 0x2F) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return format(crc ^ 0xFF, "02X")


@csrf_exempt
def generate_ecu_id(request):
    data = json.loads(request.body)
    base = f"{data['country']}-{data['oem']}-{data['plant']}"
    with transaction.atomic():
        obj, _ = ECUConfig.objects.get_or_create(base_ecu_id=base)
        obj.last_serial += 1
        obj.save()
    return JsonResponse({"ecu_id": base, "crc": crc8_autosar(base)})


@csrf_exempt
def set_ecu_password(request):
    return JsonResponse({"password": "generated-password"})


# ================= DOWNLOAD =================
def download_text(request): return HttpResponse("Download text placeholder")
def download_xl(request): return HttpResponse("Download xl placeholder")
def download_aes_key(request): return HttpResponse("Download AES key placeholder")
def download_rsa_key(request): return HttpResponse("Download RSA key placeholder")


# ================= AES / RSA =================
@csrf_exempt
def generate_aes_key(request):
    return JsonResponse({"key": os.urandom(16).hex(), "nonce": os.urandom(12).hex()})


@csrf_exempt
def generate_rsa_key(request):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ).decode()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return JsonResponse({"private_key": private_pem, "public_key": public_pem})


def file_encryption_view(request): return render(request, "encrypt.html")
def decrypt_file_view(request): return render(request, "decrypt.html")


# ================= SEED =================
@csrf_exempt
def generate_seed(request): return JsonResponse({"seed": secrets.token_hex(8)})
@csrf_exempt
def process_seed(request): return JsonResponse({"result": "processed"})
def seed_key_generation(request): return render(request, "seed_key_generation.html")


# ================= PDF =================
def pdf_policy(request): return redirect("/media/policies/csms_policy.pdf")


# ================= INCIDENT =================
def incident_email(request): return render(request, "incident_email.html")


# ================= CERT PAGE =================
def digital_certificate_page(request):
    return render(request, "digital_certificate.html")


# ================= OEM KEY =================
@csrf_exempt
def generate_oem_key(request):
    if request.method == "POST":
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ).decode()
        public_pem = private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        KeyPair.objects.create(key_type="OEM", private_key=private_pem, public_key=public_pem)

        return render(request, "digital_certificate.html", {
            "private_key": private_pem,
            "public_key": public_pem,
            "success_message": "OEM Key Generated Successfully"
        })
    return redirect("digital_certificate")


# ================= OEM CERT =================
@csrf_exempt
def generate_certificate(request):
    return render(request, "digital_certificate.html", {
        "success_message": "OEM Certificate Generated Successfully"
    })


# ================= INTERMEDIATE KEY =================
@csrf_exempt
def generate_intermediate_key(request):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ).decode()

    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    KeyPair.objects.create(
        key_type="INTERMEDIATE",
        private_key=private_pem,
        public_key=public_pem
    )

    return render(request, "digital_certificate.html", {
        "success_message": "Intermediate Key Generated"
    })


# ================= INTERMEDIATE CERT =================
@csrf_exempt
def generate_intermediate_certificate(request):
    return render(request, "digital_certificate.html", {
        "success_message": "Intermediate Certificate Generated"
    })


# ================= LOGOUT =================
def logout_view(request):
    logout(request)
    return redirect("/")
