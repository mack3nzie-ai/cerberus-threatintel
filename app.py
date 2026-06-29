# CERBERUS Entry Point
import os

# Helper to load .env variables without external dependencies
def load_dotenv():
    dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(dotenv_path):
        with open(dotenv_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, val = line.split('=', 1)
                    os.environ[key.strip()] = val.strip()

# Load env file if present
load_dotenv()

# Import the flask app from the backend package
from backend.app import app

if __name__ == '__main__':
    # Retrieve configuration from environment variables (with defaults)
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", os.environ.get("FLASK_PORT", 5000)))
    debug = os.environ.get("FLASK_DEBUG", "True").lower() == "true"
    
    print(f"[*] Starting CERBERUS on {host}:{port} (Debug={debug})...")
    app.run(host=host, port=port, debug=debug)
