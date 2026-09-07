import re
import json
import requests
import argparse
from collections import Counter

# --- CONFIGURATION (Add API Keys here if needed) ---
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"  # Optional
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Optional

# Regex Patterns for Extracting IPs and Log Signals
IP_REGEX = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
FAILED_LOGIN_REGEX = r'Failed password for (?:invalid user )?(\w+) from (' + IP_REGEX[2:-2] + r')'

def parse_auth_logs(file_path):
    """Parses auth.log for brute-force SSH login attempts."""
    print(f"[+] Analyzing Auth Logs: {file_path}")
    failed_attempts = []
    
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if "Failed password" in line:
                    ip_match = re.search(r'from (' + IP_REGEX[2:-2] + r')', line)
                    if ip_match:
                        failed_attempts.append(ip_match.group(1))
    except FileNotFoundError:
        print(f"[-] Error: File {file_path} not found.")
        return {}

    ip_counts = Counter(failed_attempts)
    return ip_counts

def check_abuseipdb(ip_address):
    """Queries AbuseIPDB API for IP reputation score."""
    if ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY":
        return {"status": "Mock Data (Add API Key)", "abuseConfidenceScore": 85}
    
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    
    try:
        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            data = response.json()
            return data['data']
        else:
            return {"error": f"API Error HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def generate_report(flagged_ips, output_file="soc_alert_report.json"):
    """Generates structured SOC incident report."""
    report_data = []
    
    print("\n[+] Enriching Threat Intel via APIs...")
    for ip, count in flagged_ips.items():
        if count >= 3:  # Threshold for Brute-force Alert
            intel = check_abuseipdb(ip)
            alert = {
                "flagged_ip": ip,
                "failed_attempts": count,
                "severity": "HIGH" if count > 10 else "MEDIUM",
                "threat_intel": intel
            }
            report_data.append(alert)
    
    with open(output_file, 'w') as f:
        json.dump(report_data, f, indent=4)
        
    print(f"\n[✔] Triage Completed! Incident Report Saved to: {output_file}")
    print(json.dumps(report_data, indent=2))

if __name__ == "__main__":
    print("==================================================")
    print("      Automated Threat Intel & SOC Log Parser     ")
    print("               Developed by Barira Jamil          ")
    print("==================================================\n")

    # Sample execution logic / CLI input
    parser = argparse.ArgumentParser(description="SOC Log Parser & Threat Intel Enricher")
    parser.add_argument("-f", "--file", help="Path to log file (e.g., auth.log)", default="sample_auth.log")
    args = parser.parse_args()

    # Create dummy sample log if not exists for testing
    try:
        with open(args.file, "x") as sample:
            sample.write("Oct 12 10:01:12 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 44321 ssh2\n")
            sample.write("Oct 12 10:01:15 server sshd[1234]: Failed password for root from 185.220.101.5 port 44322 ssh2\n"*5)
            sample.write("Oct 12 10:01:18 server sshd[1234]: Failed password for root from 185.220.101.5 port 44323 ssh2\n"*8)
    except FileExistsError:
        pass

    parsed_results = parse_auth_logs(args.file)
    generate_report(parsed_results)
