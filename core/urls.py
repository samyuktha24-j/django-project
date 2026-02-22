from django.contrib import admin
from django.urls import path, include

# 🔹 EXISTING IMPORTS (kept same)
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("admin/", admin.site.urls),

    # 🔥 ADD THIS LINE FOR LMS
    path("lms/", include("lms.urls")),

    # 🔹 EXISTING PROJECT ROUTE (kept same)
    path("", include("csms.urls")),
]

# 🔹 MEDIA SUPPORT (kept same)
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
