from django.urls import path
from . import views

urlpatterns = [

    # AUTH
    path("", views.main_login, name="main_login"),
    path("home/", views.home, name="home"),
    path("logout/", views.logout_view, name="logout"),

    # ADMIN
    path("admin-dashboard/", views.admin_dashboard, name="admin_dashboard"),
    path("incident-email/", views.incident_email, name="incident_email"),

    # CRYPTO
    path("encrypt/", views.encrypt_view, name="encrypt"),
    path("download-encrypted/", views.download_encrypted, name="download_encrypted"),
    path("decrypt/", views.decrypt_view, name="decrypt"),
    path("hashing/", views.hashing, name="hashing"),
    path("hex-view/", views.hex_view, name="hex_view"),

    # DIGITAL SIGNATURE (✅ FIXED ONLY THIS)
    path("digital-signature/", views.digital_signature, name="digital_signature"),
    path("sign-file/", views.sign_file),
    path("validate-signature/", views.validate_signature),
    path("download-signature/", views.download_signature, name="download_signature"),

    # DEBUG
    path("debug/", views.debug),
    path("debug-keygen/", views.debug_keygen),

    # CERTIFICATE
    path("digital-certificate/", views.digital_certificate_page),
     path("generate-oem-key/", views.generate_oem_key, name="generate_oem_key"),
path("download-certificate/", views.download_certificate, name="download_certificate"),
path("generate-intermediate-certificate/", views.generate_intermediate_certificate, name="generate_intermediate_certificate"),
    # SEED KEY
    path("seed-key-generation/", views.seed_key_generation),

    # ECU
    path("ecu/", views.ecu_page),
    path("generate-ecu-id/", views.generate_ecu_id),
    path("set-ecu-password/", views.set_ecu_password),

    # DASHBOARD
    path("csms-dashboard/", views.csms_dashboard),

    # KEYGEN MODULE (SAFE RESTORE)
    path("keygen/aes/", views.generate_aes),
    path("download-aes/", views.download_aes),
    path("keygen/rsa/", views.generate_rsa),
    path("download-rsa/", views.download_rsa),
    path("download-signed/", views.download_signed_firmware, name="download_signed"),
]