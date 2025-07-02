# 🔐 Threat Intel Dashboard

A simple **Python-Flask tool** to analyze IPs, URLs, and hashes using **VirusTotal**, **AbuseIPDB**, and **GeoLite2**. It displays reputation scores, country info, and threat levels in one place.

---

## ⚙️ Features

- 🔍 Lookup **IPs**, **URLs**, and **hashes**
- 🌍 Country detection for IPs
- 🛡️ VirusTotal & AbuseIPDB risk scoring
- 🟢🟡🔴 Color-coded threat levels
- 📄 Export IOCs to CSV

---

## 🚀 How to Run

### 1. Clone the repo
```bash
git clone https://github.com/Anzil-cybersec/Threat-intel-integrator.git
cd Threat-intel-integrator
```

---

### 2. Create virtual environment

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```bash
python3 -m venv venv
venv\Scripts\activate
```

---

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

---

### 4. Download GeoLite2 City DB

Download from 👉 [https://dev.maxmind.com/geoip/geolite2/](https://dev.maxmind.com/geoip/geolite2/)  
(Requires a free MaxMind account)

Save the downloaded file in the project directory as:

```
GeoLite2-City.mmdb
```

---

### 5. Run the app
```bash
python3 app.py
```

Then open your browser and go to:  
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

### 🔍 Sample Threat Feed Table Screenshot

![Threat Feed Screenshot](static/screenshot.png)
