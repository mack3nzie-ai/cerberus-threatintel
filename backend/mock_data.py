# Mock Data for Simulating OSINT & Dark Web Threat Feeds
import random
from datetime import datetime, timedelta

# Mock Onion Forums Data
MOCK_ONION_POSTS = [
    {
        "id": "onion_001",
        "forum": "BreachedForums.onion",
        "author": "CyberGaruda",
        "title": "EXCLUSIVE: Indonesian Ministry of Finance (depkeu.go.id) Database Leak",
        "content": "Selling full database dump of Indonesian depkeu.go.id. Contains 500,000 records of employees and tax payments.\nSample:\nemail: budi.sutrisno@depkeu.go.id | pass_hash: 5f4dcc3b5aa765d61d8327deb882cf99\nemail: sri.mulyani_staff@depkeu.go.id | pass_hash: 7c6a524e98b0c6093375b315b10f587c\nContact Telegram @CyberGarudaEscrow.",
        "risk_level": "HIGH",
        "matched_pattern": "depkeu.go.id"
    },
    {
        "id": "onion_002",
        "forum": "RansomForum v3",
        "author": "LockBit_ID",
        "title": "State Cybersecurity Agency (bssn.go.id) Internal Network Credentials",
        "content": "Access credentials for internal staging area of bssn.go.id.\nTarget: 103.245.12.44\nService: RDP (Port 3389)\nCredentials: Administrator | bssn_security_admin_2026!",
        "risk_level": "HIGH",
        "matched_pattern": "bssn.go.id"
    },
    {
        "id": "onion_003",
        "forum": "CryptMarket",
        "author": "BlackHatID",
        "title": "Indonesian Citizen Data - 1 Million NIK & KTP Scans",
        "content": "Selling citizen data leaked from local registration database. Contains full names, address, NIK (National ID) and phone numbers.\nFormat:\n3171012345670001;Joko Widodo;Solo;081234567890\n3273026543210002;Siti Aminah;Bandung;087812345678\nPrice: 0.05 BTC. Escrow accepted.",
        "risk_level": "HIGH",
        "matched_pattern": "NIK / KTP"
    },
    {
        "id": "onion_004",
        "forum": "Labyrinth.onion",
        "author": "ShadowBroker_Indo",
        "title": "Jakarta Local Gov Web Shell Access (jakarta.go.id)",
        "content": "Selling upload vulnerability shell access on sub-domain of jakarta.go.id.\nShell URI: http://pelayanan.jakarta.go.id/uploads/files/cmd.php\nCommand parameter: cmd\nAccess price: $200 USD Monero.",
        "risk_level": "HIGH",
        "matched_pattern": "jakarta.go.id"
    }
]

# Mock Pastebin / Github Leaks
MOCK_PASTE_LEAKS = [
    {
        "id": "paste_001",
        "source": "Pastebin.com/raw/u83Jsd",
        "title": "config_backup.env",
        "content": "PORT=8080\nDB_CONNECTION=mysql\nDB_HOST=db.kemhan.go.id\nDB_PORT=3306\nDB_DATABASE=kemhan_db\nDB_USERNAME=kemhan_admin\nDB_PASSWORD=P@ssw0rdNegaraAman2026!\nJWT_SECRET=supersecretkey123",
        "risk_level": "HIGH",
        "matched_pattern": "kemhan.go.id"
    },
    {
        "id": "paste_002",
        "source": "Github Gist Public",
        "title": "todo_list_debug.txt",
        "content": "TODO for developer:\n1. Fix SQL vulnerability in search page.\n2. Change temporary password: 'admin12345' for dev.kemenkes.go.id admin panel.\n3. Implement OAuth on production.",
        "risk_level": "MEDIUM",
        "matched_pattern": "kemenkes.go.id"
    },
    {
        "id": "paste_003",
        "source": "Ghostbin.co/paste/8fs7d",
        "title": "indonesia_isp_ips.txt",
        "content": "# List of scanned vulnerable Telkomsel and Indosat IP blocks\n182.253.12.98:8080 - Tomcat Manager (default credentials admin:admin)\n125.160.45.12:80 - Apache 2.4.49 (Path Traversal CVE-2021-41773)\n36.65.12.87:22 - SSH root password bruteforced successfully.",
        "risk_level": "MEDIUM",
        "matched_pattern": "vulnerable IP"
    }
]

# Mock Threat Feed APIs (Real OSINT style, like URLhaus)
MOCK_OSINT_FEEDS = [
    {
        "id": "feed_001",
        "feed_name": "URLhaus Malicious Feed",
        "target": "http://112.199.12.5/payload.exe",
        "threat_type": "Malware Delivery (AgentTesla)",
        "reporter": "abuse_ch",
        "status": "active",
        "severity": "HIGH"
    },
    {
        "id": "feed_002",
        "feed_name": "PhishTank Active Feeds",
        "target": "https://verification-bankmandiri-login.com/secure/",
        "threat_type": "Phishing Mandiri Bank Indonesia",
        "reporter": "phish_hunter",
        "status": "active",
        "severity": "HIGH"
    },
    {
        "id": "feed_003",
        "feed_name": "URLhaus Malicious Feed",
        "target": "http://polri.go.id.external-check.ru/invoice.zip",
        "threat_type": "Malware Injection Site (Phishing polri.go.id)",
        "reporter": "cert_id",
        "status": "active",
        "severity": "MEDIUM"
    }
]

def get_random_leak():
    # Helper to return a random threat from mock data for dynamic polling simulation
    category = random.choice(["onion", "paste", "osint"])
    if category == "onion":
        post = random.choice(MOCK_ONION_POSTS)
        return {
            "source": f"{post['forum']} (Hacker: {post['author']})",
            "severity": post['risk_level'],
            "matched_keyword": post['matched_pattern'],
            "leak_content": f"Title: {post['title']}\n\n{post['content']}"
        }
    elif category == "paste":
        leak = random.choice(MOCK_PASTE_LEAKS)
        return {
            "source": leak['source'],
            "severity": leak['risk_level'],
            "matched_keyword": leak['matched_pattern'],
            "leak_content": f"Filename: {leak['title']}\n\n{leak['content']}"
        }
    else:
        feed = random.choice(MOCK_OSINT_FEEDS)
        return {
            "source": feed['feed_name'],
            "severity": feed['severity'],
            "matched_keyword": feed['threat_type'],
            "leak_content": f"Malicious URL targeting ID Space:\nTarget: {feed['target']}\nReporter: {feed['reporter']}\nStatus: {feed['status']}"
        }
