from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login, logout

import hashlib, os, json, base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ================= LOGIN =================
def main_login(request):
    if request.method == "POST":
        user = authenticate(
            request,
            username=request.POST.get("username"),
            password=request.POST.get("password")
        )
        if user:
            login(request, user)
            return redirect("home")
    return render(request, "main_login.html")

def home(request):
    return render(request, "home.html")

def logout_view(request):
    logout(request)
    return redirect("/")

# ================= ADMIN =================
def admin_dashboard(request):
    return render(request, "admin_dashboard.html")

# ================= INCIDENT =================
def incident_email(request):
    return render(request, "incident_email.html")

# ================= HASHING =================
def hashing(request):
    hash_value = None
    error = None

    if request.method == "POST":
        file = request.FILES.get("file")
        algo = request.POST.get("algorithm")

        if file and algo:
            data = file.read()
            if algo == "sha256":
                hash_value = hashlib.sha256(data).hexdigest()
            elif algo == "sha512":
                hash_value = hashlib.sha512(data).hexdigest()
        else:
            error = "Upload file and select algorithm"

    return render(request, "hashing.html", {"hash": hash_value, "error": error})

# =========================================================
# 🔐 AES FILE ENCRYPTION
# =========================================================
def encrypt_view(request):
    result = None
    if request.method == "POST":
        uploaded = request.FILES.get("file")
        key = request.POST.get("aes_key")

        if uploaded and key:
            try:
                key_bytes = key.encode()[:32].ljust(32, b'0')
                aes = AESGCM(key_bytes)
                nonce = os.urandom(12)
                data = uploaded.read()
                encrypted = aes.encrypt(nonce, data, None)
                request.session["encrypted_data"] = base64.b64encode(nonce + encrypted).decode()
                result = "Encryption successful"
            except:
                result = "Invalid AES key"

    return render(request, "encrypt.html", {"result": result})

def download_encrypted(request):
    data = request.session.get("encrypted_data")
    if not data:
        return HttpResponse("No encrypted file found")

    binary = base64.b64decode(data)
    response = HttpResponse(binary, content_type="application/octet-stream")
    response["Content-Disposition"] = "attachment; filename=encrypted.enc"
    return response

# =========================================================
# 🔓 AES FILE DECRYPTION
# =========================================================
def decrypt_view(request):
    if request.method == "POST":
        uploaded = request.FILES.get("file")
        key = request.POST.get("aes_key")

        if uploaded and key:
            try:
                key_bytes = key.encode()[:32].ljust(32, b'0')
                aes = AESGCM(key_bytes)

                raw = uploaded.read()
                nonce = raw[:12]
                ciphertext = raw[12:]
                decrypted = aes.decrypt(nonce, ciphertext, None)

                response = HttpResponse(decrypted, content_type="application/octet-stream")
                response["Content-Disposition"] = "attachment; filename=decrypted_file"
                return response
            except:
                return render(request, "decrypt.html", {"error": "Wrong AES key or corrupted file"})

    return render(request, "decrypt.html")

# ================= DIGITAL SIGNATURE =================
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def digital_signature(request):
    signature = None
    error = None

    if request.method == "POST":
        firmware = request.FILES.get("firmware")
        private_key_text = request.POST.get("private_key")
        algo = request.POST.get("algorithm")

        if firmware and private_key_text and algo:
            try:
                private_key = serialization.load_pem_private_key(
                    private_key_text.encode(),
                    password=None,
                )
                data = firmware.read()

                if algo == "RSA":
                    sig = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
                else:
                    error = "Only RSA supported currently"
                    return render(request, "digital_signature.html", {"error": error})

                signature = base64.b64encode(sig).decode()
            except Exception as e:
                error = f"Signing failed: {str(e)}"
        else:
            error = "Fill all fields"

    return render(request, "digital_signature.html", {"signature": signature, "error": error})

def sign_file(request):
    return render(request, "sign_file.html")

def validate_signature(request):
    return render(request, "validate_signature.html")

# ================= HEX VIEW =================
def hex_view(request):
    return render(request, "hex_view.html")
def hex_view(request):
    hex_data = None
    error = None

    if request.method == "POST":
        file = request.FILES.get("file")

        if file:
            try:
                data = file.read()

                # Convert to hex
                hex_data = data.hex()

                # Optional: format nicely
                hex_data = " ".join(hex_data[i:i+2] for i in range(0, len(hex_data), 2))

            except Exception as e:
                error = str(e)
        else:
            error = "Upload a file"

    return render(request, "hex_view.html", {
        "hex_data": hex_data,
        "error": error
    })

# ================= DEBUG =================
def debug(request):
    return render(request, "debug.html")

def debug_keygen(request):
    return render(request, "debug_keygen.html")

# ================= CERTIFICATE =================
 # ================= CERTIFICATE =================
def digital_certificate_page(request):
    return render(request, "digital_certificate.html")


# ================= OEM KEY GENERATION =================
@csrf_exempt
def generate_oem_key(request):
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

    # Save for download
    request.session["private_key"] = private_pem
    request.session["public_key"] = public_pem

    return render(request, "digital_certificate.html", {
        "private_key": private_pem,
        "public_key": public_pem
    })


# ================= DOWNLOAD CERTIFICATE =================
def download_certificate(request):
    private_key = request.session.get("private_key")
    public_key = request.session.get("public_key")

    if not private_key or not public_key:
        return HttpResponse("No certificate generated yet")

    content = f"""===== OEM DIGITAL CERTIFICATE =====

--- PRIVATE KEY ---
{private_key}

--- PUBLIC KEY ---
{public_key}
"""

    response = HttpResponse(content, content_type="text/plain")
    response["Content-Disposition"] = "attachment; filename=oem_certificate.txt"
    return response


# ================= INTERMEDIATE CERTIFICATE (NEW) =================
@csrf_exempt
def generate_intermediate_certificate(request):
    subject = "Intermediate CA"
    issuer = "OEM Root CA"
    serial = os.urandom(8).hex()

    certificate_text = f"""
-----BEGIN INTERMEDIATE CERTIFICATE-----
Subject: {subject}
Issuer: {issuer}
Serial: {serial}
Valid From: 2026-01-01
Valid To: 2030-01-01
-----END INTERMEDIATE CERTIFICATE-----
"""

    # Save for display
    request.session["certificate"] = certificate_text

    return render(request, "digital_certificate.html", {
        "subject": subject,
        "issuer": issuer,
        "serial": serial,
        "valid_from": "2026-01-01",
        "valid_to": "2030-01-01",
        "fingerprint": hashlib.sha256(serial.encode()).hexdigest(),
        "certificate": certificate_text
    })
# ================= REST UNCHANGED =================
def seed_key_generation(request):
    return render(request, "seed_key.html")

def ecu_page(request):
    return render(request, "ecu.html")

@csrf_exempt
def generate_ecu_id(request):
    data = json.loads(request.body)
    readable = f"{data.get('country')}-{data.get('oem')}-{data.get('plant')}-{data.get('ecu')}-{data.get('hw')}-{data.get('date')}-{data.get('line')}"
    return JsonResponse({"readable_id": readable, "hex_id": readable.encode().hex()})

@csrf_exempt
def set_ecu_password(request):
    return JsonResponse({"message": "Password generated successfully"})

def csms_dashboard(request):
    return render(request, "csms_dashboard.html")

LAST_AES = {}
LAST_RSA = {}

@csrf_exempt
def generate_aes(request):
    global LAST_AES
    LAST_AES = {
        "mode": "AES-128-GCM",
        "key": os.urandom(16).hex(),
        "nonce": os.urandom(12).hex(),
        "tag": os.urandom(16).hex(),
    }
    return JsonResponse(LAST_AES)

def download_aes(request):
    return HttpResponse(str(LAST_AES), content_type="text/plain")

@csrf_exempt
def generate_rsa(request):
    global LAST_RSA
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
    LAST_RSA = {"private_key": private_pem, "public_key": public_pem}
    return JsonResponse(LAST_RSA)

def download_rsa(request):
    return HttpResponse(str(LAST_RSA), content_type="text/plain")

# ================= DOWNLOAD SIGNATURE =================
def download_signature(request):
    if request.method == "POST":
        sig = request.POST.get("sig_data")
        if not sig:
            return HttpResponse("No signature found")

        response = HttpResponse(sig, content_type="text/plain")
        response["Content-Disposition"] = "attachment; filename=signature.sig"
        return response

    return HttpResponse("Invalid request")

from cryptography.exceptions import InvalidSignature

from cryptography.exceptions import InvalidSignature

def validate_signature(request):
    result = None
    error = None

    if request.method == "POST":
        file = request.FILES.get("file")
        sig_file = request.FILES.get("signature")
        public_key_text = request.POST.get("public_key")

        if file and sig_file and public_key_text:
            try:
                data = file.read()

                # ✅ FIX: decode base64 signature
                signature = base64.b64decode(sig_file.read())

                public_key = serialization.load_pem_public_key(
                    public_key_text.encode()
                )

                public_key.verify(
                    signature,
                    data,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )

                result = "✅ Signature VALID"

            except InvalidSignature:
                result = "❌ Signature INVALID"
            except Exception as e:
                error = f"Error: {str(e)}"
        else:
            error = "Upload file, signature and public key"

    return render(request, "validate_signature.html", {
        "result": result,
        "error": error
    })

 # ================= SIGN FILE (FIXED SESSION SAFE) =================
def sign_file(request):
    signed_firmware_hex = None
    error = None

    if request.method == "POST":
        firmware_hex = request.POST.get("firmware_hex")
        signature_hex = request.POST.get("signature_hex")

        if firmware_hex and signature_hex:
            try:
                firmware_hex = firmware_hex.replace("\n", " ").strip()
                signature_hex = signature_hex.replace("\n", " ").strip()

                firmware_bytes = bytes.fromhex(firmware_hex)
                signature_bytes = bytes.fromhex(signature_hex)

                signed_bytes = firmware_bytes + signature_bytes

                # Convert to HEX for UI
                signed_firmware_hex = signed_bytes.hex()

                # ✅ FIX: store HEX instead of bytes
                request.session["signed_firmware"] = signed_firmware_hex

            except Exception as e:
                error = f"Invalid HEX input: {str(e)}"
        else:
            error = "Paste firmware HEX and signature HEX"

    return render(request, "sign_file.html", {
        "signed_firmware_hex": signed_firmware_hex,
        "error": error
    })

# ================= DOWNLOAD SIGNED FIRMWARE (FIXED) =================
def download_signed_firmware(request):
    hex_data = request.session.get("signed_firmware")

    if not hex_data:
        return HttpResponse("No signed firmware found")

    # Convert back HEX → bytes
    binary = bytes.fromhex(hex_data)

    response = HttpResponse(binary, content_type="application/octet-stream")
    response["Content-Disposition"] = "attachment; filename=signed_firmware.bin"
    return response