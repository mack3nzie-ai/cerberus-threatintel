import os
import time
import sqlite3
# pyrefly: ignore [missing-import]
from flask import Flask, jsonify, request, Response, send_from_directory
from flask_cors import CORS

from backend.database import init_db, get_all_alerts, get_alerts_stats, clear_database, add_alert, get_db_connection, DB_PATH
from backend.tracker import run_leak_scanner, scan_text, simulate_single_random_leak
from backend.webhook import get_webhook_config, save_webhook_config, get_simulated_logs, clear_simulated_logs
# SECURE CODING: Import input sanitization and size validator functions
from backend.security_utils import secure_sanitize_payload, sanitize_command_injection, sanitize_sql_injection

# Create Flask app. Serve frontend static assets from ../frontend
app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)  # Enable Cross-Origin Resource Sharing

# Ensure DB is initialized
init_db()

# Pre-populate database with initial scan if database is empty
def pre_populate():
    alerts = get_all_alerts()
    if not alerts:
        print("[*] Pre-populating database with initial scan...")
        run_leak_scanner()

pre_populate()

# Start background SOAR scheduling thread
from backend.scheduler import start_background_scheduler
start_background_scheduler()

@app.route('/')
def serve_index():
    return app.send_static_file('index.html')

@app.route('/api/alerts', methods=['GET'])
def api_get_alerts():
    limit = request.args.get('limit', 100, type=int)
    alerts = get_all_alerts(limit=limit)
    return jsonify(alerts)

@app.route('/api/stats', methods=['GET'])
def api_get_stats():
    stats = get_alerts_stats()
    return jsonify(stats)

@app.route('/api/clear', methods=['POST'])
def api_clear_db():
    clear_database()
    return jsonify({"status": "success", "message": "Database cleared successfully."})

@app.route('/api/scan', methods=['POST'])
def api_scan_custom_text():
    data = request.get_json() or {}
    content = data.get('content', '')
    
    if not content.strip():
        return jsonify({"status": "error", "message": "Content is empty"}), 400
        
    # SECURE CODING: Sanitize custom input block before parsing for signatures
    # This prevents XSS scripting blocks from executing in the dashboard browser rendering phase.
    content = secure_sanitize_payload(content)
        
    clear_simulated_logs()
    result = scan_text(content, "Interactive Simulator")
    
    wh_logs = []
    if result:
        # Save to DB (triggers webhook)
        alert_id = add_alert(
            source=result['source'],
            severity=result['severity'],
            matched_keyword=result['matched_keyword'],
            leak_content=result['leak_content']
        )
        time.sleep(0.5) # Give background thread a tiny moment to run
        wh_logs = get_simulated_logs()
        clear_simulated_logs()
        
        return jsonify({
            "status": "threat_detected",
            "alert": {
                "id": alert_id,
                "source": result['source'],
                "severity": result['severity'],
                "matched_keyword": result['matched_keyword'],
                "leak_content": result['leak_content'],
                "detected_at": "Just now"
            },
            "webhook_logs": wh_logs
        })
    else:
        return jsonify({
            "status": "clean",
            "message": "No known patterns or data leaks detected in the scan."
        })

@app.route('/api/simulate-leak', methods=['POST'])
def api_simulate_leak():
    try:
        clear_simulated_logs()
        
        # SECURE CODING: Utilize the newly created modular scraping generator simulator
        from backend.scrapers.leak_simulator import fetch_simulated_leaks
        mock_leaks = fetch_simulated_leaks(1)
        if not mock_leaks:
            return jsonify({"status": "error", "message": "No mock leaks generated"}), 500
            
        mock_leak = mock_leaks[0]
        
        alert_id = add_alert(
            source=mock_leak['source'],
            severity=mock_leak['severity'],
            matched_keyword=mock_leak['matched_keyword'],
            leak_content=mock_leak['leak_content']
        )
        
        time.sleep(0.5) # Give background thread a tiny moment to run
        wh_logs = get_simulated_logs()
        clear_simulated_logs()
        
        return jsonify({
            "status": "success", 
            "alert": {
                "id": alert_id,
                "source": mock_leak['source'],
                "severity": mock_leak['severity'],
                "matched_keyword": mock_leak['matched_keyword'],
                "leak_content": mock_leak['leak_content']
            },
            "webhook_logs": wh_logs
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/trigger-scan-logs', methods=['GET'])
def api_trigger_scan_logs():
    """
    Returns server-sent events to simulate real-time log scanning on the dashboard
    """
    def event_stream():
        yield "data: [~] Starting deep OSINT Crawling Engine...\n\n"
        time.sleep(0.3)
        yield "data: [*] Initializing threat intelligence database...\n\n"
        time.sleep(0.3)
        yield "data: [*] Contacting onion gateway relay...\n\n"
        time.sleep(0.5)
        
        clear_simulated_logs()
        # Run actual scan and capture logs
        logs = run_leak_scanner()
        for log in logs:
            yield f"data: {log}\n\n"
            time.sleep(0.4) # delay to make logs look cool
            
        time.sleep(0.5)
        # Fetch simulated webhook dispatches if any occurred during the scan
        wh_logs = get_simulated_logs()
        if wh_logs:
            yield "data: [*] Executing automated SOAR notifications...\n\n"
            time.sleep(0.3)
            for wl in wh_logs:
                yield f"data: {wl}\n\n"
                time.sleep(0.3)
            clear_simulated_logs()
            
        yield "data: [✔] SCAN PROCESS COMPLETED SUCCESSFULY.\n\n"
        
    return Response(event_stream(), mimetype="text/event-stream")

# --- NEW WEBHOOK CHANNELS API (SOAR) ---
@app.route('/api/webhook-settings', methods=['GET', 'POST'])
def api_webhook_settings():
    if request.method == 'GET':
        return jsonify(get_webhook_config())
        
    # POST - Save new config
    data = request.get_json() or {}
    config = {
        "url": data.get("url", ""),
        "enabled": data.get("enabled", False),
        "min_severity": data.get("min_severity", "HIGH")
    }
    save_webhook_config(config)
    
    test_success = False
    test_logs = []
    if data.get("test"):
        from backend.webhook import dispatch_webhook_alert
        test_alert = {
            "source": "CERBERUS SOAR System (Test Channel)",
            "severity": config["min_severity"],
            "matched_keyword": "Test Webhook Signal",
            "leak_content": "This is an automated test signal sent by the CERBERUS Webhook Settings Dashboard."
        }
        clear_simulated_logs()
        test_success = dispatch_webhook_alert(test_alert)
        test_logs = get_simulated_logs()
        clear_simulated_logs()
        
    return jsonify({
        "status": "success",
        "message": "Webhook settings saved successfully.",
        "config": config,
        "test_sent": data.get("test", False),
        "test_success": test_success,
        "test_logs": test_logs
    })

# --- NEW OSINT TARGET INVESTIGATOR API ---
@app.route('/api/investigate', methods=['GET'])
def api_investigate():
    target = request.args.get('target', '').strip()
    if not target:
        return jsonify({"status": "error", "message": "Target parameter is required"}), 400
        
    # SECURE CODING: Sanitize parameters to mitigate Command Injection and SQL Injection attempts
    target = sanitize_command_injection(target)
    target = sanitize_sql_injection(target)
    
    if not target:
        return jsonify({"status": "error", "message": "Invalid target parameter input"}), 400
    
    # 1. Determine if IP or Domain
    import re
    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target)
    target_type = "IP Address" if is_ip else "Domain Name"
    
    # 2. Query SQLite DB for related alerts (with wildcard escaping to prevent logic disclosure)
    conn = get_db_connection()
    cursor = conn.cursor()
    escaped_target = target.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    search_param = f"%{escaped_target}%"
    cursor.execute(
        "SELECT * FROM alerts WHERE leak_content LIKE ? ESCAPE '\\' OR source LIKE ? ESCAPE '\\' OR matched_keyword LIKE ? ESCAPE '\\' ORDER BY detected_at DESC",
        (search_param, search_param, search_param)
    )
    rows = cursor.fetchall()
    conn.close()
    
    related_alerts = [dict(row) for row in rows]
    
    # 3. Create deterministic mock profile info
    import random
    import hashlib
    seed = int(hashlib.md5(target.encode('utf-8')).hexdigest(), 16) % 10000000
    rng = random.Random(seed)
    
    threat_score = rng.randint(20, 85)
    status = "CLEAN"
    if threat_score > 70:
        status = "MALICIOUS"
    elif threat_score > 40:
        status = "SUSPICIOUS"
        
    custom_profiles = {
        "bssn.go.id": {
            "threat_score": 95,
            "status": "MALICIOUS",
            "country": "Indonesia",
            "country_code": "ID",
            "city": "Jakarta",
            "isp": "BSSN Government Network",
            "asn": "AS139234",
            "open_ports": [80, 443, 22, 3389],
            "threat_actors": ["LockBit_ID", "Desorden Group"],
            "cves": ["CVE-2023-35078", "CVE-2023-27997"]
        },
        "depkeu.go.id": {
            "threat_score": 90,
            "status": "MALICIOUS",
            "country": "Indonesia",
            "country_code": "ID",
            "city": "Jakarta",
            "isp": "Kementerian Keuangan RI",
            "asn": "AS45849",
            "open_ports": [80, 443, 3306],
            "threat_actors": ["CyberGaruda"],
            "cves": ["CVE-2021-41773"]
        },
        "kemhan.go.id": {
            "threat_score": 88,
            "status": "MALICIOUS",
            "country": "Indonesia",
            "country_code": "ID",
            "city": "Jakarta",
            "isp": "Kementerian Pertahanan RI",
            "asn": "AS55688",
            "open_ports": [80, 443, 3306, 22],
            "threat_actors": ["CyberGaruda"],
            "cves": ["CVE-2022-26134"]
        },
        "kemenkes.go.id": {
            "threat_score": 75,
            "status": "SUSPICIOUS",
            "country": "Indonesia",
            "country_code": "ID",
            "city": "Jakarta",
            "isp": "Kementerian Kesehatan RI",
            "asn": "AS17643",
            "open_ports": [80, 443, 8080],
            "threat_actors": ["BlackHatID"],
            "cves": ["CVE-2023-3824"]
        },
        "kemkes.go.id": {
            "threat_score": 75,
            "status": "SUSPICIOUS",
            "country": "Indonesia",
            "country_code": "ID",
            "city": "Jakarta",
            "isp": "Kementerian Kesehatan RI",
            "asn": "AS17643",
            "open_ports": [80, 443, 8080],
            "threat_actors": ["BlackHatID"],
            "cves": ["CVE-2023-3824"]
        },
        "103.245.12.44": {
            "threat_score": 92,
            "status": "MALICIOUS",
            "country": "Indonesia",
            "country_code": "ID",
            "city": "Jakarta",
            "isp": "BSSN Infrastructure",
            "asn": "AS139234",
            "open_ports": [3389, 22],
            "threat_actors": ["LockBit_ID"],
            "cves": ["CVE-2019-11510"]
        },
        "103.22.45.12": {
            "threat_score": 85,
            "status": "MALICIOUS",
            "country": "Indonesia",
            "country_code": "ID",
            "city": "Semarang",
            "isp": "Telkom Indonesia",
            "asn": "AS7713",
            "open_ports": [3306, 80],
            "threat_actors": ["CyberGaruda"],
            "cves": ["CVE-2020-3452"]
        }
    }
    
    # Check if target matches custom profile key
    matched_key = None
    for key in custom_profiles.keys():
        if key in target.lower():
            matched_key = key
            break
            
    if matched_key:
        profile = custom_profiles[matched_key]
        threat_score = profile["threat_score"]
        status = profile["status"]
        country = profile["country"]
        country_code = profile["country_code"]
        city = profile["city"]
        isp = profile["isp"]
        asn = profile["asn"]
        open_ports = profile["open_ports"]
        threat_actors = profile["threat_actors"]
        cves = profile["cves"]
    else:
        # Generate dynamic randomized deterministic profile
        country = rng.choice(["Indonesia", "Singapore", "United States", "Russia", "China", "Netherlands"])
        country_codes = {"Indonesia": "ID", "Singapore": "SG", "United States": "US", "Russia": "RU", "China": "CN", "Netherlands": "NL"}
        country_code = country_codes.get(country, "US")
        
        isps = {
            "ID": ["Telkom Indonesia", "Indosat Ooredoo", "Biznet Networks", "Moratelindo"],
            "SG": ["Singtel", "StarHub", "M1 Limited"],
            "US": ["Amazon Web Services", "Cloudflare, Inc.", "DigitalOcean, LLC", "Comcast Cable"],
            "RU": ["Rostelecom", "Yandex LLC", "MegaFon"],
            "CN": ["China Telecom", "China Unicom", "Tencent Building"],
            "NL": ["Leaseweb Netherlands", "Hostnet B.V.", "KPN"]
        }
        isp = rng.choice(isps.get(country_code, ["Global Hosting Network"]))
        asn = f"AS{rng.randint(1000, 150000)}"
        city = rng.choice(["Jakarta", "Surabaya", "Singapore", "New York", "Moscow", "Beijing", "Amsterdam"])
        
        available_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 8080, 9000]
        open_ports = sorted(rng.sample(available_ports, rng.randint(1, 4)))
        
        all_actors = ["CyberGaruda", "LockBit_ID", "BlackHatID", "APT29", "Desorden Group", "Lazarus Group", "Fancy Bear"]
        threat_actors = rng.sample(all_actors, rng.randint(0, 1)) if threat_score > 60 else []
        
        all_cves = ["CVE-2021-44228", "CVE-2023-35078", "CVE-2022-26134", "CVE-2023-3824", "CVE-2023-27997", "CVE-2021-41773"]
        cves = rng.sample(all_cves, rng.randint(0, 2)) if threat_score > 40 else []

    # If database contains related alerts, automatically set status to MALICIOUS
    if related_alerts:
        threat_score = max(threat_score, 88)
        status = "MALICIOUS"
        
        # Ensure we attribute to actors matching the database content
        alert_str = str(related_alerts)
        if "CyberGaruda" in alert_str and "CyberGaruda" not in threat_actors:
            threat_actors.append("CyberGaruda")
        if "LockBit_ID" in alert_str and "LockBit_ID" not in threat_actors:
            threat_actors.append("LockBit_ID")
            
    return jsonify({
        "target": target,
        "type": target_type,
        "threat_score": threat_score,
        "status": status,
        "geoip": {
            "country": country,
            "country_code": country_code,
            "city": city,
            "isp": isp,
            "asn": asn
        },
        "open_ports": open_ports,
        "threat_actors": threat_actors,
        "cves": cves,
        "related_alerts": related_alerts
    })

if __name__ == '__main__':
    # Listen on all network interfaces on port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)
