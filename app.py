from flask import Flask, request, jsonify
from flask_cors import CORS
import dns.resolver
import whois
import requests
from datetime import datetime
import socket
import ssl
import json
from urllib.parse import urlparse
import time

app = Flask(__name__)
CORS(app)

# ============================================
# API KEYS CONFIGURATION
# ============================================
# Add your API keys here (FREE to get!)
SECURITYTRAILS_API_KEY = "P1fILVOtCloPYZWPubqLvDXHLvXrcPCK"  # Get from: https://securitytrails.com/
SHODAN_API_KEY = "ypnWaAEvFNfZNtme8PP3eUVhUF6oJqeP"  # Get from: https://account.shodan.io/

# ============================================
# HELPER FUNCTIONS
# ============================================

def clean_domain(domain):
    """Remove http://, https://, www. from domain"""
    domain = domain.lower().strip()
    domain = domain.replace('http://', '').replace('https://', '')
    domain = domain.replace('www.', '')
    domain = domain.split('/')[0]
    return domain

def is_cloudflare_ip(ip):
    """Check if IP belongs to Cloudflare"""
    cloudflare_ranges = [
        '103.21.244', '103.22.200', '103.31.4', '104.16', '104.17', 
        '104.18', '104.19', '104.20', '104.21', '104.22', '104.23',
        '104.24', '104.25', '104.26', '104.27', '104.28', '104.29',
        '104.30', '104.31', '172.64', '172.65', '172.66', '172.67',
        '173.245.48', '173.245.49', '188.114.96', '188.114.97',
        '190.93.240', '197.234.240', '198.41.128'
    ]
    for cf_range in cloudflare_ranges:
        if ip.startswith(cf_range):
            return True
    return False

def get_ip_info(ip):
    """Get geolocation and hosting info for an IP"""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'org': data.get('org', 'Unknown')
            }
    except:
        pass
    return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'org': 'Unknown'}

# ============================================
# NEW: ADVANCED API FUNCTIONS
# ============================================

def get_securitytrails_history(domain):
    """Get historical DNS records from SecurityTrails"""
    if not SECURITYTRAILS_API_KEY:
        return []
    
    try:
        headers = {
            'APIKEY': SECURITYTRAILS_API_KEY,
            'Content-Type': 'application/json'
        }
        
        # Get historical A records
        url = f'https://api.securitytrails.com/v1/history/{domain}/dns/a'
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            historical = []
            
            for record in data.get('records', [])[:5]:  # Get last 5 records
                for ip in record.get('values', []):
                    if not is_cloudflare_ip(ip.get('ip', '')):
                        historical.append({
                            'date': record.get('last_seen', 'Unknown'),
                            'type': 'A',
                            'value': ip.get('ip', ''),
                            'proxied': False
                        })
            
            return historical
    except Exception as e:
        print(f"SecurityTrails error: {e}")
    
    return []

def get_shodan_info(ip):
    """Get server information from Shodan"""
    if not SHODAN_API_KEY:
        return None
    
    try:
        url = f'https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}'
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'ports': data.get('ports', []),
                'hostnames': data.get('hostnames', []),
                'org': data.get('org', 'Unknown'),
                'os': data.get('os', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'country': data.get('country_name', 'Unknown'),
                'vulns': list(data.get('vulns', {}).keys())
            }
    except Exception as e:
        print(f"Shodan error: {e}")
    
    return None

def check_wayback_machine(domain):
    """Check Wayback Machine for historical snapshots"""
    try:
        url = f'http://archive.org/wayback/available?url={domain}'
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('archived_snapshots'):
                snapshot = data['archived_snapshots'].get('closest', {})
                return {
                    'available': snapshot.get('available', False),
                    'url': snapshot.get('url', ''),
                    'timestamp': snapshot.get('timestamp', '')
                }
    except:
        pass
    
    return {'available': False}

def get_dns_over_https(domain):
    """Use Cloudflare DNS over HTTPS for better results"""
    try:
        # Cloudflare DNS over HTTPS
        url = f'https://cloudflare-dns.com/dns-query?name={domain}&type=A'
        headers = {'accept': 'application/dns-json'}
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            ips = []
            for answer in data.get('Answer', []):
                if answer.get('type') == 1:  # A record
                    ips.append(answer.get('data'))
            return ips
    except:
        pass
    
    return []

def check_urlscan(domain):
    """Check URLScan.io for website analysis"""
    try:
        # Search for recent scans
        url = f'https://urlscan.io/api/v1/search/?q=domain:{domain}'
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', [])
            if results:
                return {
                    'scanned': True,
                    'last_scan': results[0].get('task', {}).get('time', ''),
                    'url': results[0].get('result', ''),
                    'server': results[0].get('page', {}).get('server', 'Unknown')
                }
    except:
        pass
    
    return {'scanned': False}

def advanced_subdomain_scan(domain):
    """Enhanced subdomain enumeration with more techniques"""
    subdomains = []
    
    # Expanded list of common subdomains
    common_subs = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'ns3', 'ns4',
        'cpanel', 'webmail', 'admin', 'dev', 'staging', 'api', 'test',
        'blog', 'shop', 'store', 'forum', 'support', 'help', 'portal',
        'vpn', 'remote', 'cloud', 'cdn', 'assets', 'static', 'images',
        'mobile', 'app', 'secure', 'login', 'account', 'my', 'dashboard'
    ]
    
    for sub in common_subs:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            proxied = is_cloudflare_ip(ip)
            ip_info = get_ip_info(ip)
            
            subdomains.append({
                'name': subdomain,
                'ip': ip,
                'hosting': 'Cloudflare' if proxied else ip_info['isp'],
                'proxied': proxied
            })
            
            time.sleep(0.1)  # Rate limiting
        except:
            continue
    
    return subdomains

# ============================================
# MAIN API ENDPOINT (UPDATED)
# ============================================

@app.route('/api/investigate', methods=['POST'])
def investigate_domain():
    """Main investigation endpoint with advanced detection"""
    try:
        data = request.get_json()
        domain = clean_domain(data.get('domain', ''))
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400

        print(f"\n{'='*50}")
        print(f"🔍 Investigating: {domain}")
        print(f"{'='*50}")

        # Collect all investigation data
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'whoisInfo': get_whois_info(domain),
            'dnsRecords': get_dns_records(domain),
            'subdomains': advanced_subdomain_scan(domain),
            'sslCertificates': get_ssl_info(domain),
            'originServers': [],
            'securityFlags': [],
            'cloudflareDetected': False,
            'riskScore': 0,
            
            # NEW ADVANCED DATA
            'historicalDNS': get_securitytrails_history(domain) if SECURITYTRAILS_API_KEY else [],
            'waybackData': check_wayback_machine(domain),
            'urlscanData': check_urlscan(domain),
            'dnsOverHTTPS': get_dns_over_https(domain),
            'shodanData': {},
            'advancedDetection': {
                'securitytrails_used': bool(SECURITYTRAILS_API_KEY),
                'shodan_used': bool(SHODAN_API_KEY),
                'techniques_count': 0,
                'confidence_boost': 0
            }
        }

        # Analyze results
        results = analyze_results_advanced(results)
        
        print(f"✅ Investigation complete!")
        print(f"   - Origin servers found: {len(results['originServers'])}")
        print(f"   - Risk score: {results['riskScore']}%")
        print(f"{'='*50}\n")
        
        return jsonify(results)

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


def get_whois_info(domain):
    """Get WHOIS information"""
    try:
        w = whois.whois(domain)
        return {
            'registrar': w.registrar if w.registrar else 'Unknown',
            'registrationDate': str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date) if w.creation_date else 'Unknown',
            'expiryDate': str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date) if w.expiration_date else 'Unknown',
            'nameservers': list(w.name_servers) if w.name_servers else [],
            'registrantCountry': w.country if hasattr(w, 'country') else 'Unknown'
        }
    except Exception as e:
        return {
            'registrar': 'Unknown',
            'registrationDate': 'Unknown',
            'expiryDate': 'Unknown',
            'nameservers': [],
            'registrantCountry': 'Unknown',
            'error': str(e)
        }


def get_dns_records(domain):
    """Get current DNS records"""
    dns_records = {
        'current': [],
        'historical': []
    }
    
    # Get A records
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = str(rdata)
            proxied = is_cloudflare_ip(ip)
            hosting = 'Cloudflare' if proxied else get_ip_info(ip)['isp']
            dns_records['current'].append({
                'type': 'A',
                'value': f"{ip} ({hosting})",
                'proxied': proxied
            })
    except:
        pass

    # Get MX records
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            dns_records['current'].append({
                'type': 'MX',
                'value': str(rdata.exchange),
                'proxied': False
            })
    except:
        pass

    # Get TXT records
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            dns_records['current'].append({
                'type': 'TXT',
                'value': str(rdata).replace('"', '')[:50] + '...',
                'proxied': False
            })
    except:
        pass
    
    return dns_records


def get_ssl_info(domain):
    """Get SSL certificate information"""
    certificates = []
    
    try:
        # Get current SSL certificate
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                certificates.append({
                    'issuer': dict(x[0] for x in cert['issuer'])['organizationName'],
                    'validFrom': cert['notBefore'],
                    'validTo': cert['notAfter'],
                    'san': [x[1] for x in cert.get('subjectAltName', [])]
                })
    except:
        pass

    # Get historical certificates from crt.sh
    try:
        response = requests.get(f'https://crt.sh/?q={domain}&output=json', timeout=10)
        if response.status_code == 200:
            crt_data = response.json()
            for cert in crt_data[:5]:
                certificates.append({
                    'issuer': cert.get('issuer_name', 'Unknown'),
                    'validFrom': cert.get('not_before', 'Unknown'),
                    'validTo': cert.get('not_after', 'Unknown'),
                    'san': [cert.get('name_value', domain)],
                    'note': 'Historical certificate'
                })
    except:
        pass
    
    return certificates[:3]


def analyze_results_advanced(results):
    """Enhanced analysis with advanced detection techniques"""
    
    origin_servers = []
    security_flags = []
    cloudflare_detected = False
    risk_score = 0
    techniques_used = 0
    confidence_boost = 0

    # Check for Cloudflare
    for record in results['dnsRecords']['current']:
        if record.get('proxied'):
            cloudflare_detected = True
            security_flags.append({
                'type': 'info',
                'message': 'Cloudflare proxy detected on main domain',
                'severity': 'low'
            })
            break

    # Analyze subdomains
    for subdomain in results['subdomains']:
        if not subdomain['proxied']:
            ip_info = get_ip_info(subdomain['ip'])
            
            # NEW: Check Shodan for this IP
            shodan_data = get_shodan_info(subdomain['ip']) if SHODAN_API_KEY else None
            
            confidence = 85
            if shodan_data:
                confidence += 10  # Boost confidence with Shodan data
                confidence_boost += 10
                techniques_used += 1
                results['shodanData'][subdomain['ip']] = shodan_data
            
            origin_servers.append({
                'ip': subdomain['ip'],
                'confidence': min(confidence, 99),
                'source': 'Subdomain enumeration' + (' + Shodan verification' if shodan_data else ''),
                'hosting': shodan_data['org'] if shodan_data else ip_info['isp'],
                'location': f"{ip_info['city']}, {ip_info['country']}"
            })
            
            security_flags.append({
                'type': 'warning',
                'message': f"Exposed subdomain found: {subdomain['name']}",
                'severity': 'high'
            })
            risk_score += 25

    # NEW: Analyze SecurityTrails historical data
    if results['historicalDNS']:
        techniques_used += 1
        security_flags.append({
            'type': 'success',
            'message': f"Found {len(results['historicalDNS'])} historical DNS records (SecurityTrails)",
            'severity': 'medium'
        })
        
        for record in results['historicalDNS']:
            ip = record['value']
            ip_info = get_ip_info(ip)
            
            origin_servers.append({
                'ip': ip,
                'confidence': 90,  # Higher confidence from SecurityTrails
                'source': 'SecurityTrails historical DNS',
                'hosting': ip_info['isp'],
                'location': f"{ip_info['city']}, {ip_info['country']}"
            })
        
        risk_score += 20
        confidence_boost += 15

    # NEW: Analyze DNS over HTTPS results
    if results['dnsOverHTTPS']:
        techniques_used += 1
        for ip in results['dnsOverHTTPS']:
            if not is_cloudflare_ip(ip):
                security_flags.append({
                    'type': 'info',
                    'message': 'Alternative DNS resolution confirmed origin IP',
                    'severity': 'low'
                })

    # NEW: Wayback Machine analysis
    if results['waybackData'].get('available'):
        techniques_used += 1
        security_flags.append({
            'type': 'info',
            'message': f"Website archived since {results['waybackData']['timestamp'][:4]}",
            'severity': 'low'
        })

    # NEW: URLScan.io analysis
    if results['urlscanData'].get('scanned'):
        techniques_used += 1
        security_flags.append({
            'type': 'info',
            'message': f"Previously scanned on URLScan.io - Server: {results['urlscanData']['server']}",
            'severity': 'low'
        })

    # SSL certificates
    if results['sslCertificates']:
        for cert in results['sslCertificates']:
            if 'Cloudflare' not in cert['issuer']:
                security_flags.append({
                    'type': 'info',
                    'message': f"Non-Cloudflare SSL certificate found: {cert['issuer']}",
                    'severity': 'low'
                })
            else:
                security_flags.append({
                    'type': 'success',
                    'message': 'Valid SSL certificate detected',
                    'severity': 'low'
                })

    # Remove duplicates
    unique_origins = []
    seen_ips = set()
    for origin in origin_servers:
        if origin['ip'] not in seen_ips:
            unique_origins.append(origin)
            seen_ips.add(origin['ip'])

    # Update results
    results['originServers'] = unique_origins
    results['securityFlags'] = security_flags
    results['cloudflareDetected'] = cloudflare_detected
    results['riskScore'] = min(risk_score, 100)
    results['advancedDetection'] = {
        'securitytrails_used': bool(SECURITYTRAILS_API_KEY),
        'shodan_used': bool(SHODAN_API_KEY),
        'techniques_count': techniques_used + 5,  # Base techniques + advanced
        'confidence_boost': confidence_boost,
        'total_techniques': f"{techniques_used + 5} detection methods used"
    }

    return results


@app.route('/api/health', methods=['GET'])
def health_check():
    """Check if API is running and show API status"""
    api_status = {
        'securitytrails': 'configured' if SECURITYTRAILS_API_KEY else 'not configured',
        'shodan': 'configured' if SHODAN_API_KEY else 'not configured',
        'ip-api': 'available',
        'crt.sh': 'available',
        'wayback': 'available',
        'urlscan': 'available'
    }
    
    return jsonify({
        'status': 'healthy',
        'message': 'Advanced Origin Server Detector API',
        'apis': api_status,
        'version': '2.0 - Enhanced Edition'
    })


if __name__ == '__main__':
    print("=" * 60)
    print("🚀 ADVANCED Origin Server Detector API Starting...")
    print("=" * 60)
    print("📡 API will run on: http://localhost:5000")
    print("🔍 Test endpoint: http://localhost:5000/api/health")
    print("")
    print("🔑 API Configuration:")
    print(f"   SecurityTrails: {'✅ Configured' if SECURITYTRAILS_API_KEY else '❌ Not configured'}")
    print(f"   Shodan:         {'✅ Configured' if SHODAN_API_KEY else '❌ Not configured'}")
    print("")
    print("💡 To add API keys, edit the API KEYS CONFIGURATION section")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)