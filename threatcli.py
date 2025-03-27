import argparse
import requests
import pymongo
from datetime import datetime

# 🔹 MongoDB Connection
MONGO_IP = "192.168.142.4"  # Change this if needed
client = pymongo.MongoClient(f"mongodb://{MONGO_IP}:27017/")
db = client["threat_intelligence"]
collection = db["ip_reports"]

# 🔹 API Keys (Ensure these are set up)
IPINFO_API_KEY = "506a4f404d0dee"
ABUSEIPDB_API_KEY = "908c66ab2b861a99d27c2b636851af71cba6cd3ad059693f30255b2e260256c8dab2c674188e1785"
VT_API_KEY = "a41a18260eceb4fb2a83c65228a5f3334adda9f9baecf78c6f72b898a1ca7b2c"
SHODAN_API_KEY = "Qe2hnu13RxR0DVUsAmvGyZKUDST8cpen"

# 🔹 Function to get IP details
def get_ip_info(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}"
        response = requests.get(url, timeout=5).json()
        return {
            "IP": ip,
            "Country": response.get("country", "N/A"),
            "City": response.get("city", "N/A"),
            "ISP": response.get("org", "N/A")
        }
    except Exception as e:
        return {"Error": f"IPinfo API failed - {e}"}

# 🔹 Function to check AbuseIPDB
def check_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        response = requests.get(url, headers=headers, params=params, timeout=5).json()
        if "data" in response:
            abuse_score = response["data"]["abuseConfidenceScore"]
            risk_level = "✅ Safe" if abuse_score == 0 else "⚠️ Suspicious" if abuse_score < 50 else "🚨 High Risk!"
            return {"Abuse Score": f"{abuse_score} ({risk_level})"}
    except Exception as e:
        return {"Error": f"AbuseIPDB API failed - {e}"}
    return {"Abuse Score": "N/A"}

# 🔹 Function to check VirusTotal
def check_virustotal(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious_count = stats["malicious"]
            suspicious_count = stats["suspicious"]
            vt_risk = "🚨 High Risk!" if malicious_count > 5 else "⚠️ Suspicious" if suspicious_count > 0 else "✅ Safe"
            return {"VirusTotal Malicious Reports": malicious_count, "VirusTotal Risk": vt_risk}
    except Exception as e:
        return {"Error": f"VirusTotal API failed - {e}"}
    return {"VirusTotal Risk": "N/A"}

# 🔹 Function to check open ports & vulnerabilities using Shodan
def check_shodan(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url, timeout=5).json()
        if "error" in response:
            return {"Shodan Data": "No data found or API limit reached"}
        open_ports = response.get("ports", [])
        return {"Open Ports": open_ports if open_ports else "None"}
    except Exception as e:
        return {"Error": f"Shodan API failed - {e}"}

# 🔹 Function to save to MongoDB
def save_to_mongodb(data):
    try:
        data["timestamp"] = datetime.utcnow()
        collection.insert_one(data)
        print("✅ Data saved to MongoDB")
    except Exception as e:
        print(f"❌ MongoDB Insert Error: {e}")

# 🔹 Main function to get IP details
def ip_lookup(ip):
    print(f"\n🔍 Scanning IP: {ip}...\n")
    info = get_ip_info(ip)
    abuse_data = check_abuseipdb(ip)
    vt_data = check_virustotal(ip)
    shodan_data = check_shodan(ip)

    result = {**info, **abuse_data, **vt_data, **shodan_data}
    save_to_mongodb(result)

    # 🔹 Print the results in a clean format
    print("\n📌 **Threat Intelligence Report:**")
    for key, value in result.items():
        print(f"{key}: {value}")

# 🔹 Check if script is run with arguments
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Intelligence IP Lookup Tool")
    parser.add_argument("ip", nargs="?", help="IP address to scan")  # Optional argument
    args = parser.parse_args()

    if args.ip:
        ip_lookup(args.ip)
    else:
        ip = input("\nEnter an IP address to check: ").strip()
        ip_lookup(ip)
