from django.urls import path
from . import views

urlpatterns = [
    path('', views.lms_home),
    path('course/', views.course_detail),
    path('generate-hash/', views.generate_hash),
    path('encrypt/', views.encrypt_text),
    path('sign/', views.sign_text),
    path('verify/', views.verify_signature),
    path('complete/', views.mark_complete), 
     path('owasp/', views.owasp_page),
     path('learning/', views.learning_dashboard, name='learning'),
     path("generate-seed/", views.generate_seed),
path("process-seed/", views.process_seed),

 # ✅ progress route
]
