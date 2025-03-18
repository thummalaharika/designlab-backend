from django.core.mail import send_mail
import random
from django.conf import settings
from .models import User

def send_otp_via_email(email, otp):
    subject = f"OTP for login to IP Scanner"
    message = f"Your otp is {otp}"
    email_from = settings.EMAIL_HOST_USER
    send_mail(subject,message,email_from,[email])