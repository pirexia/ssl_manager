from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('generate/', views.generate_csr, name='generate_csr'),
    path('api/domain/<int:domain_id>/', views.get_domain_details, name='get_domain_details'),
    path('search/', views.search_certificates, name='search_certificates'),
    path('certificate/<int:pk>/', views.certificate_detail, name='certificate_detail'),
    path('download/<int:pk>/<str:file_type>/', views.download_file, name='download_file'),
    path('certificate/<int:pk>/upload/', views.upload_certificate, name='upload_certificate'),
    path('certificate/<int:pk>/download/<str:format>/', views.download_certificate, name='download_certificate'),
    path('certificate/<int:pk>/generate-internal/', views.generate_internal_certificate, name='generate_internal_certificate'),
    path('download-ca/<str:ca_type>/', views.download_ca_certificate, name='download_ca_certificate'),
    path('certificate/<int:pk>/delete/', views.delete_certificate, name='delete_certificate'),
    path('password_change/', views.password_change_view, name='password_change'),
    path('mfa/setup/', views.mfa_setup, name='mfa_setup'),
    path('mfa/verify-setup/', views.mfa_verify_setup, name='mfa_verify_setup'),
    path('mfa/login/', views.mfa_login_view, name='mfa_login'),
    path('cookie-consent/', views.set_cookie_consent, name='set_cookie_consent'),
]
