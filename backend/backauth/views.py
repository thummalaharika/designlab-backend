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
import os
from dotenv import load_dotenv
import requests
import time

# token 676fae567111834d79a4a69553a291c44e70379a
# Create your views here.
# to access this API: In headers, put the Authorization = "token <AUTH_TOKEN>"
load_dotenv()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT = 50  # Max 50 CVEs per 30 seconds
NVD_SLEEP_TIME = 30  # Wait 30 seconds after hitting the limit
NVD_API_KEY = os.getenv("NVD_API_KEY")
# print (NVD_API_KEY)

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

def fetch_cve_details(cve_id):
    url = f"{NVD_API_URL}?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # raise an exception for non-2xx status codes
        data = response.json()
        
        if "vulnerabilities" in data and data["vulnerabilities"]:
            cve = data["vulnerabilities"][0].get("cve", {})

            description = cve.get("descriptions", [{}])[0].get("value", "No description available")
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


# **Function to parse Vulners script output**
def parse_vulners_output(output):
    if not output:
        return []
    
    vulns = []
    for line in output:
        if line.startswith("CVE"):
            vulns.append(line.strip())  # Extract CVE IDs
    return vulns
 
    
def scan_vulnerabilities(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-sV --script vulners')
    results = []
    all_cves = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            
            for port in ports:
                try:
                    port_data = scanner[host][proto][port]
                    service = port_data.get("name","unknown")
                    version = port_data.get("version","unknown")
                    product = port_data.get("product", "unknown")

                    vuln_scripts = port_data.get("script", {})
                    vulners_output = vuln_scripts.get("vulners", "").split()
                    
                    if vulners_output:
                        cve_ids = parse_vulners_output(vulners_output)
                        all_cves.extend(cve_ids)
                    
                        for cve_id in cve_ids:    
                            results.append({
                                'port': port,
                                'service': service,
                                'product': product,
                                'version': version,
                                'vuln_id': cve_id,
                                'description': None,
                                'cvss_score': None
                            })
                except Exception as e:
                    print(f"Error scanning port {port} on {host}: {e}")
                    
    for i in range(0, len(all_cves), NVD_RATE_LIMIT):
        batch = all_cves[i:i + NVD_RATE_LIMIT]

        for cve_id in batch:
            cve_details = fetch_cve_details(cve_id)

            # **Update vulnerabilities with CVE details**
            for vuln in results:
                if vuln["vuln_id"] == cve_id:
                    vuln["description"] = cve_details.get("description")
                    vuln["cvss_score"] = cve_details.get("cvss_score")
                    print(cve_id, cve_details)

        # **Rate limiting enforcement**
        if i + NVD_RATE_LIMIT < len(all_cves):
            print(f"Rate limit reached. Sleeping for {NVD_SLEEP_TIME} seconds...")
            time.sleep(NVD_SLEEP_TIME)
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