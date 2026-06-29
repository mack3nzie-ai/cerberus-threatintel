import os
import json
import re
import requests
import threading

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'webhook_config.json')
config_lock = threading.Lock()

# Global list to store simulated logs that can be queried by the SSE endpoint or client
simulated_logs = []

def get_webhook_config():
    with config_lock:
        if not os.path.exists(CONFIG_PATH):
            default_config = {
                "url": "",
                "enabled": False,
                "min_severity": "HIGH"
            }
            try:
                with open(CONFIG_PATH, 'w') as f:
                    json.dump(default_config, f, indent=4)
            except Exception:
                pass
            return default_config
        
        try:
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            return {"url": "", "enabled": False, "min_severity": "HIGH"}

def save_webhook_config(config):
    with config_lock:
        try:
            with open(CONFIG_PATH, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving webhook config: {e}")
            return False

def add_simulated_log(message):
    simulated_logs.append(message)
    # Keep last 50 logs
    if len(simulated_logs) > 50:
        simulated_logs.pop(0)

def clear_simulated_logs():
    simulated_logs.clear()

def get_simulated_logs():
    return list(simulated_logs)

def redact_sensitive_info(message: str, webhook_url: str) -> str:
    """
    SECURE CODING: Log Sanitization & Anti-Information Leakage.
    Prevents sensitive tokens, Discord secrets, and Telegram Bot IDs from leaking 
    into standard logging systems or dashboard UI terminal outputs.
    """
    if not message:
        return ""
    
    # Redact full webhook URL
    if webhook_url and webhook_url in message:
        message = message.replace(webhook_url, "[REDACTED_WEBHOOK_URL]")
        
    # Redact Discord Webhook secret path segments: /webhooks/<id>/<token>
    message = re.sub(r'webhooks/\d+/[a-zA-Z0-9_\-]+', 'webhooks/[REDACTED_ID]/[REDACTED_SECRET]', message)
    
    # Redact Telegram Bot API Token structures: bot<token>
    message = re.sub(r'bot\d+:[a-zA-Z0-9_\-]+', 'bot[REDACTED_API_TOKEN]', message)
    
    return message

def dispatch_webhook_alert(alert_data):
    """
    SECURE CODING: Automated Threat Notification Dispatcher (SOAR).
    Forwards high-severity incident findings to external endpoints (Discord / Telegram).
    Employs robust defensive coding: input validation, strict API timeouts, and error sanitization.
    """
    # 1. DEFENSIVE DESIGN: Input validation
    if not isinstance(alert_data, dict):
        return False
        
    config = get_webhook_config()
    if not config.get("enabled") or not config.get("url"):
        return False
        
    url = config.get("url").strip()
    if not url:
        return False
    
    # 2. SEVERITY THRESHOLD CHECKING
    # Automatically triggers alert for critical status parameters
    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 3}
    alert_sev = alert_data.get("severity", "LOW").upper()
    min_sev = config.get("min_severity", "HIGH").upper()
    
    if severity_rank.get(alert_sev, 1) < severity_rank.get(min_sev, 3):
        return False
        
    # Check if dummy/simulated (doesn't contain real target API domains)
    is_dummy = "discord.com/api/webhooks" not in url and "api.telegram.org" not in url
    
    source = alert_data.get("source", "Unknown Source")
    severity = alert_data.get("severity", "LOW")
    keyword = alert_data.get("matched_keyword", "Generic Indicator")
    content = alert_data.get("leak_content", "")
    
    # Snippet content to avoid payload overflow and DoS on external notification services
    snippet = content[:600] + "..." if len(content) > 600 else content
    
    # Redact sensitive targets inside the logs to avoid credential double leaks
    redacted_url = redact_sensitive_info(url, url)
    
    if is_dummy:
        msg = f"[SOAR WEBHOOK] Simulating delivery to: {redacted_url} | Severity: {severity} | Vulnerability: {keyword}"
        print(msg)
        add_simulated_log(f"[SOAR] [Webhook Triggered] Simulated dispatch for {severity} alert to {redacted_url}")
        return True

    # 3. SECURE DISPATCH: Distinct Connect and Read Timeout margins (mitigates thread lock and hang)
    # Using (connect_timeout, read_timeout) tuple as recommended by OWASP
    http_timeout = (10.0, 15.0)

    # 1. Discord Webhook Payload
    if "discord.com/api/webhooks" in url:
        color_map = {
            "CRITICAL": 16722015, # Red (#ff2a5f)
            "HIGH": 16722015,     # Red
            "MEDIUM": 16765440,   # Yellow (#ffd200)
            "LOW": 62206          # Blue (#00f2fe)
        }
        
        embed = {
            "title": "🚨 CERBERUS - Alert Triggered",
            "description": "A dynamic signature match was identified by the OSINT Engine.",
            "color": color_map.get(severity.upper(), 62206),
            "fields": [
                {"name": "Source Feed", "value": source, "inline": True},
                {"name": "Severity Level", "value": f"**{severity}**", "inline": True},
                {"name": "Detection Category", "value": keyword, "inline": False},
                {"name": "Exposed Payload Preview", "value": f"```text\n{snippet}\n```", "inline": False}
            ],
            "footer": {
                "text": "CERBERUS SOAR System"
            }
        }
        
        payload = {"embeds": [embed]}
        
        try:
            r = requests.post(url, json=payload, timeout=http_timeout)
            if r.status_code in [200, 204]:
                add_simulated_log("[SOAR] [Webhook Success] Alert dispatched to Discord webhook successfully.")
                return True
            else:
                add_simulated_log(f"[SOAR] [Webhook Error] Discord returned status code: {r.status_code}")
                return False
        except Exception as e:
            # SECURE CODING: Sanitize exception message to prevent URL Token disclosure in error logs
            clean_err = redact_sensitive_info(str(e), url)
            add_simulated_log(f"[SOAR] [Webhook Error] Discord request failed: {clean_err}")
            return False

    # 2. Telegram Bot Webhook Payload
    elif "api.telegram.org/bot" in url:
        text = (
            f"🚨 *CERBERUS Threat Alert*\n\n"
            f"*Source:* {source}\n"
            f"*Severity:* {severity}\n"
            f"*Vulnerability:* {keyword}\n\n"
            f"*Exposed Payload Preview:*\n`{snippet}`"
        )
        
        payload = {"text": text, "parse_mode": "Markdown"}
        
        try:
            r = requests.post(url, json=payload, timeout=http_timeout)
            if r.status_code == 200:
                add_simulated_log("[SOAR] [Webhook Success] Alert dispatched to Telegram successfully.")
                return True
            else:
                add_simulated_log(f"[SOAR] [Webhook Error] Telegram returned status: {r.status_code}")
                return False
        except Exception as e:
            # SECURE CODING: Sanitize exception message to prevent Bot Token disclosure in error logs
            clean_err = redact_sensitive_info(str(e), url)
            add_simulated_log(f"[SOAR] [Webhook Error] Telegram request failed: {clean_err}")
            return False
            
    return False
