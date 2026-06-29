import random
import hashlib
from datetime import datetime, timedelta

# List of typical Indonesian target domains (Government, State-Owned Enterprises, and Corporate)
INDO_DOMAINS = [
    "bssn.go.id", "kemenkes.go.id", "depkeu.go.id", "kemhan.go.id", "polri.go.id",
    "pajak.go.id", "kemendagri.go.id", "telkom.co.id", "pertamina.com", "pln.co.id",
    "bni.co.id", "bankmandiri.co.id", "jakarta.go.id", "jabarprov.go.id"
]

# Common Indonesian names to generate realistic threat payloads
INDO_NAMES = [
    "Budi Prasetyo", "Siti Aminah", "Agus Setiawan", "Dewi Lestari", "Rudi Hartono",
    "Tri Wahyuni", "Eko Susilo", "Sri Rahayu", "Surya Wijaya", "Mega Utami",
    "Joko Susilo", "Rina Wulandari", "Ahmad Fauzi", "Kartika Sari"
]

# Simulated Dark Web Forums and Ingestion Feeds
FEEDS = [
    "BreachedForums.onion", "RansomForum v3", "CryptMarket", "Labyrinth.onion",
    "Pastebin.com/raw/u83Jsd", "Ghostbin.co/paste/8fs7d", "Github Public Gists"
]

def generate_random_credential_leak(domain=None):
    """
    Simulates a database credentials dump leak.
    """
    if not domain:
        domain = random.choice(INDO_DOMAINS)
        
    name = random.choice(INDO_NAMES)
    first_name = name.split()[0].lower()
    last_name = name.split()[1].lower()
    
    email = f"{first_name}.{last_name}@{domain}"
    password = f"P@ssw0rdNegara_{random.randint(2024, 2026)}!"
    
    # Generate MD5 or SHA256 hashes to mimic actual password leakage logs
    p_hash = hashlib.sha256(password.encode()).hexdigest()
    
    content = (
        f"--- MOCK DUMP BACKUP FILE ---\n"
        f"Database Schema: members_{domain.replace('.', '_')}\n"
        f"Exposed Row:\n"
        f"UID: {random.randint(1000, 9999)}\n"
        f"Username: {first_name}_{last_name}\n"
        f"User Email: {email}\n"
        f"Password Plain: {password}\n"
        f"Password Hash (SHA-256): {p_hash}\n"
        f"Status: admin_root"
    )
    
    return {
        "source": random.choice(FEEDS),
        "severity": "HIGH",
        "matched_keyword": f"{domain} credentials leak",
        "leak_content": content
    }

def generate_random_nik_leak():
    """
    Simulates a leaked citizen registration database containing Indonesian National IDs (NIK).
    """
    name = random.choice(INDO_NAMES)
    city = random.choice(["Jakarta", "Surabaya", "Bandung", "Medan", "Semarang", "Yogyakarta"])
    
    # Indonesian NIK format: 16 digits
    # 32 (prov) + 73 (city) + random digits
    nik = f"3273{random.randint(10, 99)}{random.randint(10000000, 99999999)}"
    phone = f"0812{random.randint(10000000, 99999999)}"
    
    content = (
        f"EXPOSED DATASET: INDONESIAN CITIZEN REGISTRY DUMP\n"
        f"Format: NIK;NAME;PLACE_OF_BIRTH;PHONE_NUMBER\n"
        f"Records:\n"
        f"{nik};{name};{city};{phone}\n"
        f"317101{random.randint(10000000, 99999999)};Agus Supriyadi;Solo;087811223344\n"
        f"Total exposed rows in partition: 12,500"
    )
    
    return {
        "source": "CryptMarket (Seller: IndoDataBroker)",
        "severity": "HIGH",
        "matched_keyword": "Indonesian National ID (NIK) Leak",
        "leak_content": content
    }

def generate_random_server_leak():
    """
    Simulates exposed web shell configs, database backups, or open ports vulnerabilities.
    """
    domain = random.choice(INDO_DOMAINS)
    ip_addr = f"103.{random.randint(10, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    
    content = (
        f"ENVIRONMENT VARIABLES CONFIG BACKUP - STAGING SERVER\n"
        f"TARGET HOST: {domain} ({ip_addr})\n"
        f"DB_CONNECTION=postgresql\n"
        f"DB_HOST={ip_addr}\n"
        f"DB_PORT=5432\n"
        f"DB_DATABASE={domain.split('.')[0]}_production\n"
        f"DB_USERNAME=admin_backend\n"
        f"DB_PASSWORD=SecureIndoPass_{random.randint(100, 999)}!\n"
        f"SYSADMIN_EMAIL=surya.wijaya@{domain}\n"
        f"DEBUG_MODE=true"
    )
    
    return {
        "source": "Github Gist Public Backup",
        "severity": "HIGH",
        "matched_keyword": f"{domain} config leak",
        "leak_content": content
    }

def generate_random_malware_feed():
    """
    Simulates malware command & control server indicators targeting Indonesian networks.
    """
    ip_addr = f"112.{random.randint(10, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    domain = random.choice(INDO_DOMAINS)
    
    content = (
        f"MALWARE DETECTED: AgentTesla C2 Injection\n"
        f"Target URL: http://{ip_addr}/payload/login_tracker.php\n"
        f"Spoofed Target: verification-{domain.replace('.go.id', '')}-login.com\n"
        f"Reporter: abuse_ch_feed\n"
        f"Status: active"
    )
    
    return {
        "source": "URLhaus Malicious Feed",
        "severity": "MEDIUM",
        "matched_keyword": "Malware Injection Site",
        "leak_content": content
    }

def fetch_simulated_leaks(count=3):
    """
    Modular OSINT Threat intelligence simulator entry point.
    Returns a list of realistic threat breach dictionaries.
    """
    scrapers = [
        generate_random_credential_leak,
        generate_random_nik_leak,
        generate_random_server_leak,
        generate_random_malware_feed
    ]
    
    results = []
    for _ in range(count):
        scraper_func = random.choice(scrapers)
        results.append(scraper_func())
        
    return results
