from django.urls import path
from . import views

urlpatterns = [

    # ================= BASIC =================
    path("", views.main_login, name="main_login"),
    path("home/", views.home, name="home"),

    path("debug/", views.debug, name="debug"),
    path("debug-keygen/", views.debug_keygen, name="debug_keygen"),

    path("csms-dashboard/", views.csms_dashboard, name="csms_dashboard"),
    path("csms-main/", views.csms_main, name="csms_main"),

    # ================= ADMIN =================
    path("admin-dashboard/", views.admin_dashboard, name="admin_dashboard"),

    # ================= ECU =================
    path("generate-ecu-id/", views.generate_ecu_id, name="generate_ecu_id"),
    path("set-ecu-password/", views.set_ecu_password, name="set_ecu_password"),

    # ================= DOWNLOAD =================
    path("download-text/", views.download_text, name="download_text"),
    path("download-xl/", views.download_xl, name="download_xl"),
    path("download-aes/", views.download_aes_key, name="download_aes_key"),
    path("download-rsa/", views.download_rsa_key, name="download_rsa_key"),

    # ================= KEY GENERATION =================
    path("keygen/aes/", views.generate_aes_key, name="generate_aes_key"),
    path("keygen/rsa/", views.generate_rsa_key, name="generate_rsa_key"),

    path("encrypt/", views.file_encryption_view, name="encrypt"),
    path("decrypt/", views.decrypt_file_view, name="decrypt"),

    # ================= SEED =================
    path("generate-seed/", views.generate_seed, name="generate_seed"),
    path("process-seed/", views.process_seed, name="process_seed"),
    path("seed-key-generation/", views.seed_key_generation, name="seed_key_generation"),

    # ================= PDF =================
    path("policies/pdf/", views.pdf_policy, name="pdf_policy"),

    # ================= INCIDENT =================
    path("incident-email/", views.incident_email, name="incident_email"),

    # ================= DIGITAL CERTIFICATE PAGE =================
    path("digital-certificate/", views.digital_certificate_page, name="digital_certificate"),

    # ================= PKI MODULE =================
    path("generate-oem-key/", views.generate_oem_key, name="generate_oem_key"),
    path("generate-oem-certificate/", views.generate_certificate, name="generate_oem_certificate"),

    path("generate-intermediate-key/", views.generate_intermediate_key, name="generate_intermediate_key"),
    path("generate-intermediate-certificate/", views.generate_intermediate_certificate, name="generate_intermediate_certificate"),
    path("logout/", views.logout_view, name="logout"),

]
