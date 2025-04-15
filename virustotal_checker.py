import requests
import argparse

API_KEY = 'YOUR_API_KEY_HERE'  # <-- Replace with your VirusTotal API key
BASE_URL = 'https://www.virustotal.com/api/v3/'

HEADERS = {
    'x-apikey': API_KEY
}


def get_analysis_type(value):
    if value.count('.') == 3 and all(part.isdigit() for part in value.split('.')):
        return 'ip_addresses'
    elif '.' in value and not value.startswith('http'):
        return 'domains'
    elif value.startswith('http'):
        return 'urls'
    else:
        return 'files'


def get_vt_data(value):
    analysis_type = get_analysis_type(value)
    
    if analysis_type == 'urls':
        # For URLs, must be base64 encoded
        import base64
        url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        endpoint = f"{BASE_URL}urls/{url_id}"
    else:
        endpoint = f"{BASE_URL}{analysis_type}/{value}"
    
    response = requests.get(endpoint, headers=HEADERS)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats.get('malicious', 0)
        print(f"[+] VT Report for {value} --> Malicious detections: {malicious}")
        return "Malicious" if malicious > 0 else "Clean"
    else:
        print(f"[-] Error: {response.status_code}, {response.text}")
        return "Error"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VirusTotal checker for IP, Domain, URL or Hash")
    parser.add_argument("value", help="IP address, domain, URL or file hash to scan")
    args = parser.parse_args()
    
    result = get_vt_data(args.value)
    print(f"[*] Result: {result}")