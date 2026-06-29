import unittest
import json
import os
import sqlite3
import sys

# Ensure backend directory is in the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import app
from backend.database import init_db, clear_database, get_all_alerts, add_alert, get_db_connection
from backend.tracker import scan_text, run_leak_scanner
from backend.security_utils import (
    sanitize_xss,
    sanitize_command_injection,
    sanitize_sql_injection,
    validate_input_size
)

class TestSecurityUtils(unittest.TestCase):
    def test_sanitize_xss(self):
        # Verify that HTML characters are escaped
        dirty = "<script>alert('XSS')</script>"
        clean = sanitize_xss(dirty)
        self.assertNotIn("<script>", clean)
        self.assertIn("&lt;script&gt;", clean)
        
        # Test empty input
        self.assertEqual(sanitize_xss(""), "")
        self.assertEqual(sanitize_xss(None), "")

    def test_sanitize_command_injection(self):
        # Verify shell control characters are stripped
        dirty = "target.com; cat /etc/passwd"
        clean = sanitize_command_injection(dirty)
        self.assertNotIn(";", clean)
        self.assertEqual(clean, "target.com cat /etc/passwd")

    def test_sanitize_sql_injection(self):
        # Verify quotes are preserved for parameterized query safety, but SQL comments are removed
        dirty = "admin' OR '1'='1' --"
        clean = sanitize_sql_injection(dirty)
        self.assertEqual(clean, "admin' OR '1'='1' ")

    def test_validate_input_size(self):
        # Verify text is truncated to maximum size
        large_text = "A" * 12000
        truncated = validate_input_size(large_text, max_limit=1000)
        self.assertEqual(len(truncated), 1000)
        
        # Verify normal size is untouched
        normal_text = "Hello World"
        self.assertEqual(validate_input_size(normal_text), normal_text)


class TestThreatTracker(unittest.TestCase):
    def test_scan_text_government_leak(self):
        # Test gov email matching
        text = "Confidential files leaked from staff@bssn.go.id"
        result = scan_text(text, "Test Source")
        self.assertIsNotNone(result)
        self.assertEqual(result["severity"], "MEDIUM")
        self.assertIn("Indonesian Government Domain/Email Leak", result["matched_keyword"])
        self.assertIn("staff@bssn.go.id", result["matches"])

        # Test gov email + password (should raise severity to HIGH)
        text_with_pass = "budi@depkeu.go.id has password = secret123"
        result_high = scan_text(text_with_pass, "Test Source")
        self.assertIsNotNone(result_high)
        self.assertEqual(result_high["severity"], "HIGH")

    def test_scan_text_nik_leak(self):
        # Test 16-digit NIK matching
        text = "Exposed NIK list: 3273011212890001; Joko; Solo"
        result = scan_text(text, "Test Source")
        self.assertIsNotNone(result)
        self.assertEqual(result["severity"], "HIGH")
        self.assertIn("Indonesian National ID (NIK) Leak", result["matched_keyword"])
        self.assertIn("3273011212890001", result["matches"])

    def test_scan_text_credentials_leak(self):
        # Test db credentials pattern matching
        text = "db_password = mysecretprodpass"
        result = scan_text(text, "Test Source")
        self.assertIsNotNone(result)
        self.assertEqual(result["severity"], "HIGH")
        self.assertIn("Exposed Database Credentials", result["matched_keyword"])

    def test_scan_text_clean(self):
        # Test text with no threat signatures
        text = "This is a normal email willy@gmail.com and clean documentation."
        result = scan_text(text, "Test Source")
        self.assertIsNone(result)


class TestDatabaseOperations(unittest.TestCase):
    def setUp(self):
        # Initialize/reset database before each test
        init_db()
        clear_database()

    def test_add_and_get_alert(self):
        # Add test alert
        alert_id = add_alert(
            source="Test Source Unit",
            severity="high",
            matched_keyword="Test Pattern",
            leak_content="Sample raw data leaked"
        )
        self.assertIsNotNone(alert_id)
        
        # Query alerts
        alerts = get_all_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source"], "Test Source Unit")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["matched_keyword"], "Test Pattern")
        self.assertEqual(alerts[0]["leak_content"], "Sample raw data leaked")

    def test_clear_database(self):
        add_alert("Src", "low", "keyword", "content")
        self.assertEqual(len(get_all_alerts()), 1)
        
        clear_database()
        self.assertEqual(len(get_all_alerts()), 0)


class TestFlaskEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        init_db()
        clear_database()

    def test_serve_index(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_api_get_stats_empty(self):
        response = self.client.get('/api/stats')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["severity"]["HIGH"], 0)

    def test_api_scan_endpoint_threat(self):
        # Scan with threat payload
        payload = {"content": "Exposed credential db_password = SecurePass2026"}
        response = self.client.post('/api/scan', 
                                    data=json.dumps(payload),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "threat_detected")
        self.assertEqual(data["alert"]["severity"], "HIGH")
        self.assertIn("Exposed Database Credentials", data["alert"]["matched_keyword"])

    def test_api_scan_endpoint_clean(self):
        # Scan with clean payload
        payload = {"content": "This is a clean documentation file."}
        response = self.client.post('/api/scan', 
                                    data=json.dumps(payload),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "clean")

    def test_api_scan_endpoint_empty(self):
        # Scan with empty payload (should raise 400 Bad Request)
        payload = {"content": "   "}
        response = self.client.post('/api/scan', 
                                    data=json.dumps(payload),
                                    content_type='application/json')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "error")
        self.assertIn("Content is empty", data["message"])

    def test_api_investigate_malicious_target(self):
        # Add an alert to cross reference
        add_alert(
            source="Test Source",
            severity="HIGH",
            matched_keyword="Exposed NIK",
            leak_content="Leaked data for kemhan.go.id"
        )
        
        # Investigate domain
        response = self.client.get('/api/investigate?target=kemhan.go.id')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["target"], "kemhan.go.id")
        self.assertEqual(data["status"], "MALICIOUS")
        self.assertGreater(data["threat_score"], 80)
        self.assertGreater(len(data["related_alerts"]), 0)

    def test_api_investigate_with_quote(self):
        # Insert alert with quote in content
        add_alert(
            source="Test Source",
            severity="HIGH",
            matched_keyword="Exposed Creds",
            leak_content="User input contains O'Connor database credentials"
        )
        # Search for O'Connor
        response = self.client.get('/api/investigate?target=O\'Connor')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        # Expecting to find it, but if sanitize_sql_injection is buggy, it might fail to find it
        self.assertEqual(len(data["related_alerts"]), 1)

    def test_api_investigate_wildcard_escaping(self):
        # Insert alerts
        add_alert(
            source="Test Source A",
            severity="MEDIUM",
            matched_keyword="Pattern A",
            leak_content="Normal government domain kemkes.go.id"
        )
        add_alert(
            source="Test Source B",
            severity="HIGH",
            matched_keyword="Pattern B",
            leak_content="Database password exposed with 100% certainty"
        )
        
        # Search for '%' wildcard. Correct implementation should only match literal '%' in second alert.
        response = self.client.get('/api/investigate?target=%')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data["related_alerts"]), 1)
        self.assertIn("100% certainty", data["related_alerts"][0]["leak_content"])

    def test_api_investigate_empty_target(self):
        response = self.client.get('/api/investigate?target=')
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()
