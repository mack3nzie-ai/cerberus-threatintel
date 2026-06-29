import threading
import time

def start_background_scheduler():
    """
    Spawns a background daemon thread that periodically runs the OSINT scanner.
    """
    def scheduler_loop():
        # Avoid circular imports by importing tracker inside the thread loop
        from backend.tracker import run_leak_scanner
        print("[*] Background SOAR Threat Scheduler started.")
        
        # Initial sleep to let Flask boot up completely
        time.sleep(10)
        
        while True:
            try:
                print("[*] Background Scheduler: Running automated OSINT threat scan...")
                # Run scan (updates DB and fires webhooks for high severity alerts)
                logs = run_leak_scanner()
                print(f"[+] Background Scheduler scan complete. Summary: {logs[-1]}")
            except Exception as e:
                print(f"[x] Error in background scheduler loop: {e}")
            
            # Wait 5 minutes (300 seconds) before next scan
            time.sleep(300)

    # Launch daemon thread
    threading.Thread(target=scheduler_loop, daemon=True).start()
