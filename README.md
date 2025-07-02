# 🔐 Threat Intel Dashboard

A simple **Python-Flask tool** to analyze IPs, URLs, and hashes using **VirusTotal**, **AbuseIPDB**, and **GeoLite2**. It displays reputation scores, country info, and threat levels in one place.

---

## ⚙️ Features

- Lookup IPs, URLs, and hashes  
- Country detection for IPs  
- VirusTotal & AbuseIPDB risk scoring  
- Color-coded risk levels  
- Export IOCs to CSV

---

## 🚀 How to Run

```bash
# 1. Clone the repo
git clone https://github.com/Anzil-cybersec/Threat-intel-integrator.git
cd Threat-intel-integrator

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # or use venv\Scripts\activate on Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Download GeoLite2 City DB
# 👉 https://dev.maxmind.com/geoip/geolite2/ (requires free MaxMind account)
# Save the file in your project folder as: GeoLite2-City.mmdb

# 5. Run the app
python3 app.py 
Then open: [http://127.0.0.1:5000](http://127.0.0.1:5000)
