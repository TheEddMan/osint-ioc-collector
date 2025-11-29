📘 OSINT IOC Collector

A fully automated Open-Source Threat Intelligence Collector that gathers Indicators of Compromise (IOCs) from multiple reputable OSINT feeds, enriches them, stores them in a local database, exports STIX 2.1, and provides a simple dashboard for viewing and analyzing threat data.
This project was originally built on a Raspberry Pi and later converted into a platform-independent Python application suitable for running on any machine or cloud environment.

🚀 Features
🔍 Multiple OSINT Feed Collectors

The system automatically collects IOCs from:
  URLHaus — malware distribution URLs
  ThreatFox — command-and-control & malware infrastructure
  MalwareBazaar — malware samples (hashes)
  PhishTank — phishing URLs
  OTX (AlienVault) — optional pulse lookups (if you add an API key)

IOCs include:
  IP addresses
  Domains
  URLs
  File hashes (MD5/SHA1/SHA256)

🧠 IOC Enrichment

Automatically enriches indicators with:
  GeoIP location (country, city, lat/lon)
  ISP & ASN (IP address owner)
  Basic URL reputation scoring
  WHOIS (optional)
  VirusTotal hash lookup (optional, requires API key)

💾 Storage

Stores all processed IOCs in a SQLite database (osint.db)

Ensures no duplicates (unique index on type/value/source)

Records timestamps for “first seen”

📦 STIX 2.1 Export

The system generates:
  output/stix/latest_bundle.json


A valid, standards-based STIX 2.1 Bundle containing the collected indicators.
Perfect for threat intel workflows, SIEM ingestion, or portfolio demos.

🌐 Web Dashboard

A lightweight dashboard built with Flask, featuring:
  Recent IOCs table
  Search/filter bar
  Auto-refreshing page (every 60 seconds)
  Line graph of IOCs per day (last 7 days)
  Simple threat-intel overview
  
Launch it locally by running:
  python -m dashboard.flask_app

Then open:
  http://localhost:5000/

📁 Project Structure
osint-ioc-collector/
│── collector/
│── parser/
│── enrichment/
│── database/
│── dashboard/
│── output/
│── run_all.py
│── requirements.txt
│── README.md
│── .gitignore

🧩 Requirements

Python 3.9+

pip

(optional) VirusTotal API Key

(optional) OTX API Key & user ID

Install dependencies:

pip install -r requirements.txt

🛠️ How to Run the Collector
Step 1 — Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

Step 2 — Install dependencies
pip install -r requirements.txt

Step 3 — Run the entire pipeline
python run_all.py


This will:

Initialize osint.db

Collect from all configured feeds

Enrich the indicators

Store everything in SQLite

Generate a STIX 2.1 bundle under output/stix/

🌐 How to Run the Dashboard
python -m dashboard.flask_app


Open:
http://localhost:5000/


You will see:
  IOC table
  Timeline graph
  Search bar
  Auto-updating threat intel data

🔧 Configuration
Environment variables (optional)

Set these before running collectors:
  VirusTotal hash lookups

  export VT_API_KEY="your_api_key_here"


OTX pulse search

Edit these in collector/feed_collector.py:
  OTX_API_KEY = ""
  OTX_USER_ID = ""

☁️ Hosting / Cloud Notes

This project is designed to run:
  Locally


Inside GitHub Actions (scheduled harvesting)

With a static front-end via GitHub Pages (optional advanced setup)

If you want a GitHub Pages + Actions version, ask and I can generate that for you.

📜 Disclaimer

This project is intended for educational, research, and defensive security purposes only.
Do not use the information or tools in this repository for malicious or illegal activity.

⭐ Author

Maintained by @theeddman
