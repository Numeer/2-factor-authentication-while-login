from django.urls import path
from otp_app.views import (RegisterView, LoginView,
                           GenerateOTP, VerifyOTP, ValidateOTP, DisableOTP)

urlpatterns = [
    path('', RegisterView.as_view(),name='register'),
    path('login', LoginView.as_view(),name = 'login'),
    path('otp/generate', GenerateOTP.as_view(),name='generate'),
    path('otp/verify', VerifyOTP.as_view(),name='verify'),
    path('otp/validate', ValidateOTP.as_view(),name='validate'),
    path('otp/disable', DisableOTP.as_view(),name='disable'),
]
