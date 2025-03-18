from django.db import models
from django.contrib.auth.models import User


# Create your models here.
class History(models.Model):
    name = models.CharField(max_length=100)

class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=6)

    def __str__(self):
        return f"OTP for {self.user.username}: {self.otp_code}"