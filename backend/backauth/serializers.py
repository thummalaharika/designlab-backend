from rest_framework import serializers
from .models import *
from django.contrib.auth.models import User
import random


class HistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = History
        fields = '__all__'

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password', 'email']
        extra_kwargs = {'password': {'write_only': True}} 

class OTPGenerateSerializer(serializers.ModelSerializer):
    class Meta:
        model = OTP
        fields = ['user']

    def create(self, validated_data):
        user = validated_data['user']
        otp_code = str(random.randint(100000, 999999))  
        
        otp = OTP.objects.create(user=user, otp_code=otp_code)
        return otp


class OTPVerifySerializer(serializers.Serializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    otp_code = serializers.CharField(max_length=6)

    def validate(self, data):
        user = data['user']
        otp_code = data['otp_code']

        otp = OTP.objects.filter(user=user, otp_code=otp_code).first()

        if not otp or not otp.is_valid():
            raise serializers.ValidationError("Invalid or expired OTP")

        return data