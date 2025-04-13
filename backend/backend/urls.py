"""
URL configuration for backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from backauth.views import *
urlpatterns = [
    path("admin/", admin.site.urls),
    path("history/", HistoryApi.as_view()),
    path("login/", LoginAPI.as_view()),
    path('signup/', SignupAPI.as_view()),
    path('ipscan/', IPScannerAPI.as_view()),
    path('generateotp/', OTPGenerateView.as_view(), name='otp-generate'),
    path('verifyotp/', OTPVerifyView.as_view(), name='otp-verify'),
    path('reset/', ResetPasswordAPI.as_view(), name='reset'),
]
