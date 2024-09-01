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
import requests
from urllib.parse import urlparse

def get_context(content, start, end, context_size=50):
    context_start = max(0, start - context_size)
    context_end = min(len(content), end + context_size)
    return content[context_start:context_end]

def normalize_url(url, base_url):
    if url.startswith('//'):
        return 'https:' + url
    elif not url.startswith(('http://', 'https://')):
        return urllib.parse.urljoin(base_url, url)
    return url

def is_js_file(url):
    return '.js' in url.lower()

async def run_jsluice(url, mode, session, verbose):
    try:
        async with session.get(url, timeout=30) as response:
            content = await response.text()
            if verbose:
                print(f"Fetched: {url}")

            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name

            cmd = f"jsluice {mode} -R '{url}' {temp_file_path}"
            if verbose:
                print(f"Running command: {cmd}")
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            os.unlink(temp_file_path)  # Remove the temporary file

            if stderr and verbose:
                print(f"Error processing {url}: {stderr.decode()}", file=sys.stderr)
            return stdout.decode().splitlines(), content
    except Exception as e:
        if verbose:
            print(f"Error in run_jsluice for {url}: {str(e)}", file=sys.stderr)
        return [], ""

async def process_jsluice_output(jsluice_output, current_url, content, verbose):
    js_urls = set()
    non_js_urls = set()
    secrets = []

    if verbose:
        print(f"Processing output for {current_url}")
        print(f"JSluice output lines: {len(jsluice_output)}")

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
                    if is_js_file(new_url):
                        js_urls.add(new_url)
                    else:
                        non_js_urls.add(new_url)
            elif 'kind' in data:
                data['original_file'] = current_url
                secrets.append(data)
        except json.JSONDecodeError:
            if verbose:
                print(f"Error decoding JSON: {line}", file=sys.stderr)

    if verbose:
        print(f"Found {len(js_urls)} JavaScript URLs")
        print(f"Found {len(non_js_urls)} non-JavaScript URLs")
        print(f"Found {len(secrets)} secrets from JSluice")

    # Add custom checks
    secrets.extend(check_aws_cognito(content, current_url))
    secrets.extend(check_razorpay(content, current_url))
    secrets.extend(check_mapbox(content, current_url))
    secrets.extend(check_fcm(content, current_url))
    secrets.extend(check_digitalocean(content, current_url))
    secrets.extend(check_tugboat(content, current_url))
    secrets.extend(check_internal_ips(content, current_url))
    secrets.extend(check_graphql_introspection(content, current_url))
    secrets.extend(check_jwt_none_algorithm(content, current_url))
    secrets.extend(check_cors_misconfig(content, current_url))

    if verbose:
        print(f"Total secrets after custom checks: {len(secrets)}")

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
curl -H "Origin: https://attacker.com" -I {current_url}
'''
        secrets.append({
            'kind': 'CORSMisconfiguration',
            'data': {'value': 'CORS Misconfiguration detected', 'matched_string': match.group()},
            'filename': current_url,
            'severity': 'medium',
            'context': context,
            'poc': poc,
            'description': f"Overly permissive CORS policy detected in {current_url}. This may allow unintended cross-origin requests."
        })
    return secrets

def verify_cors_misconfig(url):
    try:
        headers = {'Origin': 'https://attacker.com'}
        response = requests.options(url, headers=headers, timeout=5)
        if 'Access-Control-Allow-Origin' in response.headers:
            if response.headers['Access-Control-Allow-Origin'] == '*' or response.headers['Access-Control-Allow-Origin'] == 'https://attacker.com':
                return True
    except:
        pass
    return False

def check_aws_cognito(content, current_url):
    secrets = []
    cognito_markers = [
        'identityPoolId', 'cognitoIdentityPoolId', 'userPoolWebClientId', 'userPoolId',
        'aws_user_pools_id', 'aws_cognito_identity_pool_id', 'AWSCognitoIdentityProviderService',
        'CognitoIdentityCredentials', 'AWS.CognitoIdentityServiceProvider', 'cognitoUser'
    ]

    for marker in cognito_markers:
        match = re.search(rf'{marker}\s*[=:]\s*["\']?([^"\']+)["\']?', content)
        if match:
            secrets.append({
                'kind': 'AWSCognitoConfiguration',
                'data': {'marker': marker, 'matched_string': match.group()},
                'filename': current_url,
                'severity': 'info',
                'context': None
            })

    pool_id_regex = r'(us|ap|ca|cn|eu|sa)-[a-z]+-\d:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
    pool_ids = re.finditer(pool_id_regex, content)
    for match in pool_ids:
        secrets.append({
            'kind': 'AWSCognitoPoolID',
            'data': {'value': match.group(), 'matched_string': match.group()},
            'filename': current_url,
            'severity': 'medium',
            'context': None
        })

    partial_pool_id_regex = r'(us|ap|ca|cn|eu|sa)-[a-z]+-\d[:\w-]{10,}'
    partial_pool_ids = re.finditer(partial_pool_id_regex, content)
    for match in partial_pool_ids:
        if match.group() not in [s['data']['value'] for s in secrets if s['kind'] == 'AWSCognitoPoolID']:
            secrets.append({
                'kind': 'PossibleAWSCognitoPoolID',
                'data': {'value': match.group(), 'matched_string': match.group()},
                'filename': current_url,
                'severity': 'low',
                'context': None
            })

    # Check for potential Cognito tokens
    token_regex = r'eyJraWQiOiJ[\w-]+\.[\w-]+\.[\w-]+'
    token_matches = re.finditer(token_regex, content)
    for match in token_matches:
        token = match.group()
        token_type = validate_cognito_token(token)
        if token_type:
            secrets.append({
                'kind': f'AWSCognito{token_type}Token',
                'data': {'value': token[:20] + '...', 'matched_string': match.group()},
                'filename': current_url,
                'severity': 'high' if token_type == 'Authenticated' else 'medium',
                'context': None
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

async def recursive_process(initial_url, session, processed_urls, verbose):
    if initial_url in processed_urls:
        return set(), set(), []
    processed_urls.add(initial_url)

    urls_output, content = await run_jsluice(initial_url, 'urls', session, verbose)
    secrets_output, _ = await run_jsluice(initial_url, 'secrets', session, verbose)

    js_urls, non_js_urls, secrets = await process_jsluice_output(urls_output + secrets_output, initial_url, content, verbose)

    tasks = []
    for url in js_urls:
        if url not in processed_urls:
            tasks.append(recursive_process(url, session, processed_urls, verbose))

    results = await asyncio.gather(*tasks)

    for result_js_urls, result_non_js_urls, result_secrets in results:
        js_urls.update(result_js_urls)
        non_js_urls.update(result_non_js_urls)
        secrets.extend(result_secrets)

    return js_urls, non_js_urls, secrets

def severity_to_int(severity):
    severity_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    return severity_map.get(severity.lower(), -1)

async def main():
    parser = argparse.ArgumentParser(description="JSluice URL and Secrets Processor")
    parser.add_argument('-m', '--mode', choices=['endpoints', 'secrets', 'both'], default='both',
                        help="Specify what to hunt for: endpoints, secrets, or both (default: both)")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Enable verbose output")
    args = parser.parse_args()

    print("Debug: Starting main function")
    print(f"Debug: Mode: {args.mode}, Verbose: {args.verbose}")

    all_urls = set()
    all_secrets = []
    processed_urls = set()

    async with aiohttp.ClientSession() as session:
        tasks = []
        for initial_url in sys.stdin:
            initial_url = initial_url.strip()
            if initial_url:
                print(f"Debug: Processing URL: {initial_url}")
                tasks.append(recursive_process(initial_url, session, processed_urls, args.verbose))

        print(f"Debug: Total tasks created: {len(tasks)}")
        results = await asyncio.gather(*tasks)
        print("Debug: All tasks completed")

        for js_urls, non_js_urls, secrets in results:
            all_urls.update(non_js_urls)
            all_secrets.extend(secrets)

    print(f"Debug: Total URLs found: {len(all_urls)}")
    print(f"Debug: Total secrets found: {len(all_secrets)}")

    if args.mode in ['endpoints', 'both']:
        print("Debug: Printing endpoints")
        for url in sorted(all_urls):
            print(url)

    if args.mode in ['secrets', 'both']:
        print("Debug: Processing and printing secrets")
        sorted_secrets = sorted(all_secrets, key=lambda x: (-severity_to_int(x['severity']), json.dumps(x)))
        unique_secrets = list(OrderedDict((json.dumps(secret), secret) for secret in sorted_secrets).values())

        for secret in unique_secrets:
            print(json.dumps(secret))

    if args.verbose:
        print(f"Total URLs processed: {len(processed_urls)}")
        print(f"Total unique non-JS URLs found: {len(all_urls)}")
        print(f"Total secrets found: {len(all_secrets)}")

    print("Debug: Main function completed")

if __name__ == "__main__":
    asyncio.run(main())
