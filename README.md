# ThreatCLI - A Terminal-Based Threat Intelligence Tool

🚀 **ThreatCLI** is an open-source, terminal-based **Threat Intelligence** tool designed to **fetch, enrich, and analyze threat data** from multiple sources. Inspired by tools like **Nmap**, it provides quick and efficient threat lookups directly from the command line.


---

## ⚡ Features
✅ **IP Lookup & Enrichment** – Fetch threat intelligence reports for IPs in real-time.  
✅ **Custom Threat Intelligence Feeds** – Aggregate data from sources like **AlienVault OTX**, **AbuseIPDB**, and **VirusTotal**.  
✅ **MongoDB Integration** – Stores previously scanned IPs for quick lookups.  
✅ **Automation & Efficiency** – Runs scans only when an IP isn’t already in the database.  
✅ **CLI-Based Interface** – No web dashboard for now, making it lightweight and easy to use.  

---

## 🚀 Installation
### 1️⃣ Clone the Repository
```bash
git clone https://github.com/Anashashim11/ThreatCLI.git
cd ThreatCLI
```

### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 3️⃣ Configure MongoDB
Make sure MongoDB is running and configured for remote access.

### 4️⃣ Run ThreatCLI
```bash
python threatcli.py --ip <IP-Address>
```

---

## 🔥 How It Works
1. Checks if the IP exists in the **MongoDB database**.  
2. If **found**, it returns stored results.  
3. If **not found**, it fetches threat intelligence from configured sources.  
4. **Stores results** for future lookups.  

---

## 🎯 Upcoming Features
📌 **More Threat Sources** – Integration with additional OSINT APIs.  
📌 **Custom Reports** – Generate detailed threat reports.  
📌 **Improved Performance** – Optimize scanning and storage mechanisms.  
📌 **Possible Web Dashboard** – Future expansion into a web-based UI.  
