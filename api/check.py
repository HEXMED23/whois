# api/check.py
import socket
import re
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS # لتمكين CORS للطلبات من الواجهة الأمامية

app = Flask(__name__)
CORS(app) # تفعيل CORS لجميع المسارات

# WHOIS servers لكل نطاق
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "co":  "whois.nic.co",
    "xyz": "whois.nic.xyz",
    "io":  "whois.nic.io",
    "online": "whois.nic.online", # يمكن إضافة المزيد هنا
    "app": "whois.nic.google" # مثال آخر
}

WHOIS_PORT = 43
TIMEOUT = 8  # seconds

def format_date(s):
    """Format date if possible"""
    if not s:
        return "Not available"
    s = s.strip()
    try:
        s2 = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s2)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return s

def whois_raw(domain, tld):
    """Raw WHOIS query حسب النطاق"""
    ascii_domain = domain.encode("idna").decode("ascii")
    server = WHOIS_SERVERS.get(tld)
    if not server:
        raise ValueError(f"❌ WHOIS server not configured for .{tld}")

    with socket.create_connection((server, WHOIS_PORT), timeout=TIMEOUT) as sock:
        sock.sendall((ascii_domain + "\r\n").encode("utf-8"))
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.decode("utf-8", errors="ignore")

def sanitize_keyword(keyword):
    """Clean keyword to be valid as a domain name"""
    name = re.sub(r"[^a-z0-9-]+", "", keyword.strip().lower())
    if not name or name.startswith("-") or name.endswith("-"):
        return None
    return name

def check_domain(keyword, tld="com"):
    """تحقق من توافر النطاق المختار"""
    name = sanitize_keyword(keyword)
    if not name:
        return {
            "domain": None,
            "available": None,
            "status": "Invalid keyword",
            "error": "The keyword is not valid as a domain name.",
        }

    domain = f"{name}.{tld}"
    try:
        resp = whois_raw(domain, tld)
    except Exception as e:
        return {
            "domain": domain,
            "available": None,
            "status": "Check failed",
            "error": str(e),
        }

    if re.search(r'No match for\s+"?%s"?\b' % re.escape(domain.upper()), resp, re.I):
        return {"domain": domain, "available": True, "status": "Available for registration"}

    if re.search(r'^\s*Domain Name:\s*%s\b' % re.escape(domain.upper()), resp, re.I | re.M):
        registrar = re.search(r'^\s*Registrar:\s*(.+)$', resp, re.M)
        created = re.search(r'^\s*Creation Date:\s*(.+)$', resp, re.M)
        expiry  = re.search(r'^\s*Registry Expiry Date:\s*(.+)$', resp, re.M)
        return {
            "domain": domain,
            "available": False,
            "status": "Registered",
            "registrar": registrar.group(1).strip() if registrar else "Unknown",
            "creation_date": format_date(created.group(1) if created else ""),
            "expiration_date": format_date(expiry.group(1) if expiry else ""),
        }

    return {
        "domain": domain,
        "available": None,
        "status": "Check failed",
        "raw": resp[:400], # return a snippet of raw response for debugging
    }

@app.route('/check', methods=['POST'])
def check_domain_api():
    data = request.get_json()
    keyword = data.get('keyword')
    tld = data.get('tld')

    if not keyword or not tld:
        return jsonify({"error": "Keyword and TLD are required"}), 400

    result = check_domain(keyword, tld)
    return jsonify(result)

# لضمان تشغيل التطبيق محليًا
if __name__ == "__main__":
    app.run(debug=True, port=5000)
