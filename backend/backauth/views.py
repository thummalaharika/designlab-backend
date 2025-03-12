from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import *
from .serializers import *
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
import nmap
import ipaddress
from rest_framework.exceptions import ValidationError
from rest_framework import status

# token 676fae567111834d79a4a69553a291c44e70379a
# Create your views here.
# to access this API: In headers, put the Authorization = "token <AUTH_TOKEN>"
class HistoryApi(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        queryset = History.objects.all()
        serializer = HistorySerializer(queryset, many=True)
        return Response({
            "status":True,
            "data": serializer.data
        })
    
class LoginAPI(APIView):
    def post(self, request):
        data = request.data
        serializer = LoginSerializer(data=data)
        if not serializer.is_valid():
            return Response({
                "status":False,
                "message":serializer.errors
            })
        print(data)
        username = serializer.data['username']
        password = serializer.data['password']

        user_obj = authenticate(username=username, password=password)

        if user_obj:
            token,_ = Token.objects.get_or_create(user=user_obj)
            print("login successful")
            return Response({
                "status":True,
                "data":{'token':str(token)}
            })
        

        return Response({
            "status":True,
            "data":{},
            "message":"Invalid credentials"
        })

class SignupAPI(APIView):
    def post(self, request):
        data = request.data
        serializer = UserSerializer(data=data)

        if not serializer.is_valid():
            return Response({
                "status": False,
                "message": serializer.errors
            })
        
        username = serializer.validated_data['username']
        email = serializer.validated_data.get('email', '')
        
        if User.objects.filter(username=username).exists():
            return Response(
                {"error": "User with this username already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if email and User.objects.filter(email=email).exists():
            return Response(
                {"error": "User with this email already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )


        # Create the user
        user_obj = User.objects.create_user(
            username=serializer.validated_data['username'],
            password=serializer.validated_data['password'],
            email=serializer.validated_data.get('email', '')
        )

        # Generate a token for the new user
        token, _ = Token.objects.get_or_create(user=user_obj)

        return Response({
            "status": True,
            "message": "User created successfully!",
            "data": {
                "token": str(token)
            }
        })


# Utility function to validate IP

def validate_ip_addr(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def scan_vulnerabilities(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-sV --script vulners')
    results = []
    
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            
            for port in ports:
                service = scanner[host][proto][port]
                vulners_output = service.get('script', {}).get('vulners', 'No vulnerabilities found')
                
                results.append({
                    'port': port,
                    'service': service.get('name', ''),
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'vulnerabilities': vulners_output
                })
    
    return results


# API view for IP scanning
class IPScannerAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        ip_address = data.get('ip_address')
        
        if not ip_address:
            return Response({
                "status": False,
                "message": "IP address is required."
            }, status=400)
        
        if not validate_ip_addr(ip_address):
            return Response({
                "status": False,
                "message": "Invalid IP address."
            }, status=400)
        
        try:
            scan_results = scan_vulnerabilities(ip_address)
            
            return Response({
                "status": True,
                "ip_address": ip_address,
                "scan_results": scan_results
            })
            
        except Exception as e:
            return Response({
                "status": False,
                "message": f"An error occurred: {str(e)}"
            }, status=500)