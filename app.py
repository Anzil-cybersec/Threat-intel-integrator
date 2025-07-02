from flask import Flask, render_template, request, redirect, send_file, url_for
import json, os, requests, csv, re
import geoip2.database

app = Flask(__name__)

ABUSEIPDB_API_KEY = "03a90246d0d26befa307ba9bf738682eed5ce22027dc60d9f14b870b805d2077e2a4cf7f67824db4"
VT_API_KEY = "53901f3ed291f6b40312b3627095272dd98fb02bfec5877081ef7f4796cdd14d"
IOCS_FILE = "iocs.json"
GEOIP_DB = "GeoLite2-City.mmdb"

# Load/Save Functions
def load_iocs():
    if not os.path.exists(IOCS_FILE):
        return []
    with open(IOCS_FILE, "r") as f:
        return json.load(f)

def save_iocs(data):
    with open(IOCS_FILE, "w") as f:
        json.dump(data, f, indent=2)

# Validators
def is_ip(ioc):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc)

def is_url(ioc):
    return ioc.startswith("http://") or ioc.startswith("https://")

def is_hash(ioc):
    return re.match(r"^[a-fA-F0-9]{32,64}$", ioc)

# Get Country from IP
def get_country(ip):
    try:
        reader = geoip2.database.Reader(GEOIP_DB)
        return reader.city(ip).country.name
    except:
        return "N/A"

# Fetch AbuseIPDB Score
def fetch_abuseipdb(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers)
        return r.json()['data']['abuseConfidenceScore']
    except:
        return 0

# Fetch VirusTotal Data
def fetch_virustotal(ioc, ioc_type):
    endpoint = ""
    if ioc_type == "ip":
        endpoint = f"ip_addresses/{ioc}"
    elif ioc_type == "url":
        endpoint = "urls/" + re.sub(r'\W', '', ioc)
    elif ioc_type == "hash":
        endpoint = f"files/{ioc}"
    else:
        return 0
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    try:
        r = requests.get(url, headers=headers)
        return r.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
    except:
        return 0

@app.route('/')
def home():
    return render_template("dashboard.html", iocs=load_iocs())

@app.route('/submit', methods=['POST'])
def submit():
    ioc = request.form["ip"]
    note = request.form.get("note", "")
    iocs = load_iocs()

    if any(entry["ioc"] == ioc for entry in iocs):
        return redirect('/')

    # Determine type
    if is_ip(ioc):
        ioc_type = "ip"
    elif is_url(ioc):
        ioc_type = "url"
    elif is_hash(ioc):
        ioc_type = "hash"
    else:
        return redirect('/')

    vt_score = fetch_virustotal(ioc, ioc_type)
    abuse_score = fetch_abuseipdb(ioc) if ioc_type == "ip" else 0
    total_score = vt_score + abuse_score
    country = get_country(ioc) if ioc_type == "ip" else "N/A"

    new_entry = {
        "ioc": ioc,
        "type": ioc_type,
        "abuse_confidence": abuse_score,
        "vt_malicious": vt_score,
        "total_risk": total_score,
        "country": country,
        "note": note
    }

    iocs.append(new_entry)
    save_iocs(iocs)
    return redirect('/')

@app.route('/export')
def export_csv():
    iocs = load_iocs()
    with open("iocs.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["IOC", "Type", "AbuseIPDB", "VT", "Total", "Risk Level", "Country", "Note"])
        for i in iocs:
            level = "High" if i["total_risk"] >= 50 else "Medium" if i["total_risk"] >= 10 else "Low"
            writer.writerow([
                i["ioc"], i["type"], i["abuse_confidence"], i["vt_malicious"],
                i["total_risk"], level, i["country"], i["note"]
            ])
    return send_file("iocs.csv", as_attachment=True)

@app.route('/clear')
def clear():
    save_iocs([])
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
