import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    # Make sure backend directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            severity TEXT NOT NULL,
            matched_keyword TEXT NOT NULL,
            leak_content TEXT NOT NULL,
            detected_at TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()
    print(f"Database initialized at: {DB_PATH}")

def add_alert(source, severity, matched_keyword, leak_content):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    detected_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute('''
        INSERT INTO alerts (source, severity, matched_keyword, leak_content, detected_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (source, severity.upper(), matched_keyword, leak_content, detected_at))
    
    conn.commit()
    alert_id = cursor.lastrowid
    conn.close()
    
    # Trigger webhook dispatch in a background thread to prevent blocking
    try:
        from backend.webhook import dispatch_webhook_alert
        alert_data = {
            "id": alert_id,
            "source": source,
            "severity": severity,
            "matched_keyword": matched_keyword,
            "leak_content": leak_content,
            "detected_at": detected_at
        }
        import threading
        threading.Thread(target=dispatch_webhook_alert, args=(alert_data,), daemon=True).start()
    except Exception as e:
        print(f"Error dispatching webhook in database.py: {e}")
        
    return alert_id

def get_all_alerts(limit=100):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts ORDER BY detected_at DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def get_alerts_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Total count
    cursor.execute('SELECT COUNT(*) as total FROM alerts')
    total = cursor.fetchone()['total']
    
    # Severity breakdown
    cursor.execute('SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity')
    severity_rows = cursor.fetchall()
    severity_breakdown = {row['severity']: row['count'] for row in severity_rows}
    
    # Fill in default values if not present
    for sev in ['HIGH', 'MEDIUM', 'LOW']:
        if sev not in severity_breakdown:
            severity_breakdown[sev] = 0
            
    # Source breakdown
    cursor.execute('SELECT source, COUNT(*) as count FROM alerts GROUP BY source')
    source_rows = cursor.fetchall()
    source_breakdown = {row['source']: row['count'] for row in source_rows}
    
    conn.close()
    
    return {
        'total': total,
        'severity': severity_breakdown,
        'source': source_breakdown
    }

def clear_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM alerts')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
