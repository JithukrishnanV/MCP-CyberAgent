import requests
import subprocess
import os
import tempfile
from dotenv import load_dotenv
import subprocess

# Load API key from env file
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '../configs/api_keys.env'))
VT_API_KEY = os.getenv("VT_API_KEY")


VT_API_URL = "https://www.virustotal.com/api/v3/files/"

def get_virus_details(hash_value):
    headers = {'x-apikey': VT_API_KEY}
    url = VT_API_URL + hash_value
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get('data', {}).get('attributes', {})
            scan_results = data.get('last_analysis_results', {})
            threat_name = data.get('popular_threat_name', 'Unknown')
            malicious_count = data.get('last_analysis_stats', {}).get('malicious', 0)

            malicious_engines = [
                f"{engine}: {result['result']}"
                for engine, result in scan_results.items()
                if result['category'] == 'malicious'
            ]

            return {
                'hash': hash_value,
                'threat_name': threat_name,
                'malicious_count': malicious_count,
                'malware_info': malicious_engines
            }
        elif response.status_code == 404:
            return {"hash": hash_value, "error": "Hash not found in VirusTotal."}
        else:
            return {"hash": hash_value, "error": f"API error {response.status_code}"}
    except Exception as e:
        return {"hash": hash_value, "error": str(e)}

def get_hashes_from_ps1():
    ps1_path = os.path.join(os.path.dirname(__file__), 'sysinfo.ps1').replace("\\", "/")

    try:
        result = subprocess.run(
            ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", ps1_path],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            print("⚠️ PowerShell error:", result.stderr)
            return []

        output = result.stdout.strip()
        print(output)
        return output.split(",") if output else []
    except Exception as e:
        return [f"🚫 Error: {str(e)}"]

def scan_hashes_from_ps1():
    """
    High-level function Claude or bridge will call.
    Gets hashes from Zabimaru.ps1, queries VirusTotal, and summarizes findings.
    Returns formatted string summary for Claude.
    """
    hashes = get_hashes_from_ps1()
    results = []
    
    for h in hashes:
        details = get_virus_details(h)
        if 'malicious_count' in details and details['malicious_count'] > 0:
            report = (
                f"🔍 Hash: {details['hash']}\n"
                f"- Threat Name: {details['threat_name']}\n"
                f"- Malicious Engines Detected: {details['malicious_count']}\n"
                f"- Detections:\n"
                + "\n".join(f"  - {line}" for line in details['malware_info'])
            )
            results.append(report)
        elif 'error' in details:
            results.append(f"⚠️ {details['hash']} - {details['error']}")
        else:
            results.append(f"✅ {details['hash']} - No malicious findings")
    
    print("\n\n".join(results))
    return "\n\n".join(results)
scan_hashes_from_ps1()