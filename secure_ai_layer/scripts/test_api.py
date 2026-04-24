import requests
import sqlite3
import time
import sys

def main():
    print("[1] Waiting for server to initialize...")
    time.sleep(2)
    
    url = "http://127.0.0.1:8000/v1/chat/completions"
    payload = {
        "user_message": "Tell me my current account balance",
        "session_id": "hackathon_test_session"
    }
    
    print(f"[2] Sending request to {url}")
    try:
        response = requests.post(url, json=payload, timeout=10)
        print(f"Status Code: {response.status_code}")
        print("Response JSON:", response.json())
    except Exception as e:
        print("Request failed:", e)
        sys.exit(1)
        
    print("[3] Verifying audit database logs...")
    try:
        conn = sqlite3.connect("audit.db")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 1")
        row = cursor.fetchone()
        if row:
            print("Found Latest Audit Log:")
            for key in row.keys():
                print(f"  {key}: {row[key]}")
        else:
            print("No records found in audit_logs!")
    except Exception as e:
        print("Audit DB check failed:", e)

if __name__ == "__main__":
    main()
