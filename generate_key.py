# generate_key.py
import base64
from datetime import datetime

# Set your expiry date (YYYY-MM-DD)
expiry = "2025-11-30"
data = f"SIEBEL-LOG-ANALYZER-TCS-TOOL-LICENSE-VALIDITY|{expiry}"
encoded = base64.b64encode(data.encode()).decode()

with open("license.key", "w") as f:
    f.write(encoded)

print("License key generated:", encoded)