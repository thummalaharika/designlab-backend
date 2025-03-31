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
from rest_framework.permissions import AllowAny
from .models import OTP
from .serializers import OTPGenerateSerializer, OTPVerifySerializer
from rest_framework import status, generics
from django.contrib.auth.models import User
from django.conf import settings
from django.core.mail import send_mail
import time
from functools import wraps
import re
import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT = 50  # Max 50 CVEs per 30 seconds
NVD_SLEEP_TIME = 30  # Wait 30 seconds after hitting the limit
NVD_API_KEY = os.getenv("NVD_API_KEY")
# print (NVD_API_KEY)

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


# def scan_vulnerabilities(ip):
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

#### NEW CODE BEGINNING ####
def fetch_cve_details(cve_id):
    """
    Fetch CVE details (description and CVSS score) for a single CVE ID.
    :param cve_id: CVE ID to fetch details for.
    :return: Dictionary containing description and CVSS score.
    """
    url = f"{NVD_API_URL}?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an error for HTTP issues
        data = response.json()

        if "vulnerabilities" in data and data["vulnerabilities"]:
            cve = data["vulnerabilities"][0].get("cve", {})

            # Extract description
            description = cve.get("descriptions", [{}])[0].get("value", "No description available")

            # Extract CVSS score (try CVSSv3 first, then fallback to CVSSv2)
            cvss_metrics = cve.get("metrics", {})
            cvss_score = None

            if "cvssMetricV31" in cvss_metrics:
                cvss_score = cvss_metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in cvss_metrics:
                cvss_score = cvss_metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in cvss_metrics:
                cvss_score = cvss_metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            return {
                "description": description,
                "cvss_score": cvss_score if cvss_score is not None else "Unknown"
            }

    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVE details for {cve_id}: {e}")

    return {"description": "Error fetching details", "cvss_score": "Unknown"}


def parse_vulners_output(output):
    """Parse and sanitize Vulners script output."""
    if not output:
        return []
    
    vulns = []
    for line in output:
        if line.startswith("CVE"):
            vulns.append(line)
            # print(line)
    return vulns

def scan_vulnerabilities(ip):
    """Scan vulnerabilities for a given IP address"""
    try:
        validate_ip_addr(ip)
        print(f"Scanning IP: {ip}")  # Debugging

        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-sV --script vulners")

        vulnerabilities = []
        all_cves = []

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    try:
                        port_data = nm[host][proto][port]
                        service = port_data.get("name", "unknown")
                        version = port_data.get("version", "unknown")
                        product = port_data.get("product", "unknown")

                        vuln_scripts = port_data.get("script", {})
                        vulners_output = vuln_scripts.get("vulners", "").split()

                        if vulners_output:
                            cve_ids = parse_vulners_output(vulners_output)
                            all_cves.extend(cve_ids)

                            for cve_id in cve_ids:
                                vulnerabilities.append({
                                    "port": port,
                                    "service": service,
                                    "product": product,
                                    "version": version,
                                    "vuln_id": cve_id,
                                    "Description": None, # Placeholder to be filled later
                                    "CVSS Score": None # Placeholder to be filled later
                                })

                    except Exception as e:
                        print(f"Error processing vulnerabilities on port {port}: {str(e)}")

        # **Process CVEs in batches of 50 to follow rate limits**
        for i in range(0, len(all_cves), NVD_RATE_LIMIT):
            batch = all_cves[i:i + NVD_RATE_LIMIT]

            for cve_id in batch:
                cve_details = fetch_cve_details(cve_id)

                # **Update vulnerabilities with CVE details**
                for vuln in vulnerabilities:
                    if vuln["vuln_id"] == cve_id:
                        vuln["Description"] = cve_details.get("description")  # ✅ Correctly updating details
                        vuln["CVSS_Score"] = cve_details.get("cvss_score")  # ✅ Correctly updating details
                        print(cve_id)
                        print(cve_details)
                        print('\n')

            # **Wait 30 seconds if more than 50 CVEs**
            if i + NVD_RATE_LIMIT < len(all_cves):
                print(f"Rate limit reached. Sleeping for {NVD_SLEEP_TIME} seconds...")
                time.sleep(NVD_SLEEP_TIME)

    except Exception as e:
        print(f"Error scanning vulnerabilities for {ip}: {str(e)}")
    return vulnerabilities

#### NEW CODE ENDING ####


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
        

class OTPGenerateView(generics.CreateAPIView):
    queryset = OTP.objects.all()
    serializer_class = OTPGenerateSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')

        try:
            user = User.objects.get(email=email)  # Fetch user using email
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist"}, status=status.HTTP_404_NOT_FOUND)

        # Generate a random 6-digit OTP
        otp_code = random.randint(100000, 999999)

        # Save OTP in the database
        OTP.objects.create(user=user, otp_code=otp_code)

        # Send OTP via email
        subject = "Your OTP Code"
        message = f"Hello {user.username},\n\nYour OTP code is: {otp_code}\n\nDo not share this code with anyone."
        sender_email = settings.EMAIL_HOST_USER  # Replace with your email
        recipient_email = [user.email]

        send_mail(subject, message, sender_email, recipient_email, fail_silently=False)

        return Response({"message": "OTP sent successfully via email"}, status=status.HTTP_201_CREATED)


class OTPVerifyView(generics.GenericAPIView):
    serializer_class = OTPVerifySerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        otp_code = request.data.get('otp_code')

        try:
            user = User.objects.get(email=email)  # Fetch user using email
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist"}, status=status.HTTP_404_NOT_FOUND)

        otp = OTP.objects.filter(user=user, otp_code=otp_code).first()

        if otp :
            otp.delete()  # Delete OTP after successful verification
            token, _ = Token.objects.get_or_create(user=user)

            return Response({
                "message": "OTP verified successfully",
                "token": str(token),
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)
