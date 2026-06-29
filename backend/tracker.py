import re
import requests
from backend.database import add_alert, get_all_alerts
from backend.mock_data import MOCK_ONION_POSTS, MOCK_PASTE_LEAKS, MOCK_OSINT_FEEDS, get_random_leak

# Signature Patterns for Leak Detection
PATTERN_GO_ID = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]*\.go\.id\b|\b[A-Za-z0-9.-]+\.go\.id\b', re.IGNORECASE)
PATTERN_NIK = re.compile(r'\b\d{16}\b') # Indonesian National ID: 16 digits
PATTERN_CREDENTIAL = re.compile(r'db_password\s*=\s*[^\s]+|db_pass\s*=\s*[^\s]+|password\s*:\s*[^\s]+|\badmin\s*\|\s*[^\s]+', re.IGNORECASE)

def fetch_live_urlhaus_feed(limit=25):
    """
    SECURE CRAWLER: Connects to the real URLhaus threat feed to pull recent malicious URLs.
    Fails gracefully by returning an empty list if there's no internet connectivity.
    """
    try:
        # Fetch JSON payload of recent threat indicators from abuse.ch URLhaus
        r = requests.get("https://urlhaus.abuse.ch/downloads/json_recent/", timeout=8)
        if r.status_code == 200:
            data = r.json()
            items = []
            for url_id, entries in data.items():
                for entry in entries:
                    items.append({
                        "url": entry.get("url"),
                        "threat_type": entry.get("threat", "Malware Delivery"),
                        "reporter": entry.get("reporter", "abuse_ch"),
                        "dateadded": entry.get("dateadded"),
                        "status": entry.get("url_status", "offline")
                    })
            return items[:limit]
    except Exception as e:
        print(f"[*] Live URLhaus feed fetch failed: {e}")
    return []
def fetch_live_openphish_feed(limit=25):
    """
    SECURE CRAWLER: Connects to the public OpenPhish feed to pull active phishing URLs.
    Fails gracefully by returning an empty list if there's no internet connectivity.
    """
    try:
        # OpenPhish provides a free plain-text list of active phishing URLs
        r = requests.get("https://openphish.com/feed.txt", timeout=8)
        if r.status_code == 200:
            urls = [line.strip() for line in r.text.splitlines() if line.strip()]
            return urls[:limit]
    except Exception as e:
        print(f"[*] Live OpenPhish feed fetch failed: {e}")
    return []

def scan_text(text, source_name):
    """
    Scans a given text block against regex signatures.
    Returns a dict with detection results if an anomaly/leak is found, else None.
    """
    detections = []
    
    # Check for .go.id patterns (Government leak)
    go_id_matches = PATTERN_GO_ID.findall(text)
    if go_id_matches:
        detections.append({
            "type": "Indonesian Government Domain/Email Leak",
            "matches": list(set(go_id_matches)),
            "severity": "HIGH" if "password" in text.lower() or "db_" in text.lower() else "MEDIUM"
        })
        
    # Check for NIK (PII Leak)
    nik_matches = PATTERN_NIK.findall(text)
    if nik_matches:
        detections.append({
            "type": "Indonesian National ID (NIK) Leak",
            "matches": list(set(nik_matches)),
            "severity": "HIGH"
        })
        
    # Check for credentials
    cred_matches = PATTERN_CREDENTIAL.findall(text)
    if cred_matches:
        detections.append({
            "type": "Exposed Database Credentials",
            "matches": list(set(cred_matches)),
            "severity": "HIGH"
        })
        
    if not detections:
        return None
        
    # Determine overall severity and matched keyword description
    highest_severity = "LOW"
    types = []
    all_matches = []
    for det in detections:
        types.append(det["type"])
        all_matches.extend(det["matches"])
        if det["severity"] == "HIGH":
            highest_severity = "HIGH"
        elif det["severity"] == "MEDIUM" and highest_severity != "HIGH":
            highest_severity = "MEDIUM"
            
    return {
        "source": source_name,
        "severity": highest_severity,
        "matched_keyword": ", ".join(types),
        "leak_content": text,
        "matches": all_matches
    }

def run_leak_scanner():
    """
    Main function to fetch from feeds and save alerts into DB.
    Returns logs of scanning process.
    """
    logs = []
    alerts_found = 0
    
    logs.append("[*] Initializing OSINT Threat Scanner Engine...")
    
    # 1. Scan Simulated Onion Forums
    logs.append("[*] Scanning simulated dark web forums (.onion)...")
    for post in MOCK_ONION_POSTS:
        logs.append(f"    [>] Crawling {post['forum']} - Title: '{post['title'][:30]}...'")
        result = scan_text(post['content'], f"{post['forum']} ({post['author']})")
        if result:
            # Check if this alert already exists (simple content check)
            existing = get_all_alerts()
            already_exists = any(a['leak_content'] == result['leak_content'] for a in existing)
            if not already_exists:
                add_alert(
                    source=result['source'],
                    severity=result['severity'],
                    matched_keyword=result['matched_keyword'],
                    leak_content=result['leak_content']
                )
                logs.append(f"    [!] ALERT DETECTED ({result['severity']}): {result['matched_keyword']}")
                alerts_found += 1
                
    # 2. Scan Simulated Paste Sites
    logs.append("[*] Crawling pastebins & Github public gists...")
    for paste in MOCK_PASTE_LEAKS:
        logs.append(f"    [>] Crawling {paste['source']} - Title: '{paste['title']}'")
        result = scan_text(paste['content'], paste['source'])
        if result:
            existing = get_all_alerts()
            already_exists = any(a['leak_content'] == result['leak_content'] for a in existing)
            if not already_exists:
                add_alert(
                    source=result['source'],
                    severity=result['severity'],
                    matched_keyword=result['matched_keyword'],
                    leak_content=result['leak_content']
                )
                logs.append(f"    [!] ALERT DETECTED ({result['severity']}): {result['matched_keyword']}")
                alerts_found += 1
                
    # 3. Process Malware OSINT Feeds
    logs.append("[*] Connecting to live URLhaus API feed...")
    live_items = fetch_live_urlhaus_feed(limit=25)
    
    if live_items:
        logs.append(f"[+] Successfully fetched {len(live_items)} recent live threats from URLhaus.")
        for item in live_items:
            url_str = item["url"]
            logs.append(f"    [>] Scanning live target: {url_str[:50]}...")
            
            # Check if this URL targets Indonesian space (contains .id, .go.id, .co.id, etc.)
            is_indonesian_target = ".id" in url_str.lower()
            
            # Scan URL string against signature patterns
            result = scan_text(url_str, "URLhaus Live Feed")
            
            if is_indonesian_target or result:
                severity = "HIGH" if ".go.id" in url_str.lower() else "MEDIUM"
                matched_keyword = result["matched_keyword"] if result else "Malicious URL Targeting ID Space"
                
                existing = get_all_alerts()
                already_exists = any(url_str in a['leak_content'] for a in existing)
                if not already_exists:
                    content = f"Target: {url_str}\nReporter: {item['reporter']}\nType: {item['threat_type']}\nDate Added: {item['dateadded']}\nStatus: {item['status']}"
                    add_alert(
                        source=f"URLhaus Live Feed ({item['reporter']})",
                        severity=severity,
                        matched_keyword=matched_keyword,
                        leak_content=content
                    )
                    logs.append(f"    [!] LIVE ALERT DETECTED ({severity}): {matched_keyword} -> {url_str[:40]}...")
                    alerts_found += 1
    else:
        logs.append("[!] Failed to fetch live URLhaus feed. Falling back to mock feed data...")
        for feed in MOCK_OSINT_FEEDS:
            logs.append(f"    [>] Fetching {feed['feed_name']} - Target: {feed['target'][:30]}...")
            existing = get_all_alerts()
            already_exists = any(feed['target'] in a['leak_content'] for a in existing)
            if not already_exists:
                content = f"Target: {feed['target']}\nReporter: {feed['reporter']}\nType: {feed['threat_type']}"
                add_alert(
                    source=feed['feed_name'],
                    severity=feed['severity'],
                    matched_keyword=feed['threat_type'],
                    leak_content=content
                )
                logs.append(f"    [!] ALERT DETECTED ({feed['severity']}): {feed['threat_type']}")
                alerts_found += 1

    # 4. Process Phishing OSINT Feeds (OpenPhish)
    logs.append("[*] Connecting to live OpenPhish feed...")
    phish_urls = fetch_live_openphish_feed(limit=25)
    if phish_urls:
        logs.append(f"[+] Successfully fetched {len(phish_urls)} recent live phishing targets from OpenPhish.")
        for p_url in phish_urls:
            logs.append(f"    [>] Scanning live phishing target: {p_url[:50]}...")
            
            # Check if target is Indonesian space (.id)
            is_indonesian_target = ".id" in p_url.lower()
            result = scan_text(p_url, "OpenPhish Live Feed")
            
            if is_indonesian_target or result:
                severity = "HIGH" if ".go.id" in p_url.lower() else "MEDIUM"
                matched_keyword = result["matched_keyword"] if result else "Phishing Site Targeting ID Space"
                
                existing = get_all_alerts()
                already_exists = any(p_url in a['leak_content'] for a in existing)
                if not already_exists:
                    content = f"Target Phishing URL: {p_url}\nSource: OpenPhish Community Feed\nThreat: Credential Theft / Phishing Phobos"
                    add_alert(
                        source="OpenPhish Live Feed",
                        severity=severity,
                        matched_keyword=matched_keyword,
                        leak_content=content
                    )
                    logs.append(f"    [!] LIVE PHISHING ALERT ({severity}): {matched_keyword} -> {p_url[:40]}...")
                    alerts_found += 1
    else:
        logs.append("[!] Failed to fetch live OpenPhish feed or no online URLs found.")
            
    logs.append(f"[+] Scan completed. Added {alerts_found} new alerts to database.")
    return logs

def simulate_single_random_leak():
    """
    Simulates a new leak discovered in real time.
    """
    leak = get_random_leak()
    result = scan_text(leak['leak_content'], leak['source'])
    
    # Use random severity from leak if scan_text didn't catch (e.g. for malware logs)
    severity = result['severity'] if result else leak['severity']
    matched_keyword = result['matched_keyword'] if result else leak['matched_keyword']
    
    alert_id = add_alert(
        source=leak['source'],
        severity=severity,
        matched_keyword=matched_keyword,
        leak_content=leak['leak_content']
    )
    return {
        "id": alert_id,
        "source": leak['source'],
        "severity": severity,
        "matched_keyword": matched_keyword,
        "leak_content": leak['leak_content']
    }
