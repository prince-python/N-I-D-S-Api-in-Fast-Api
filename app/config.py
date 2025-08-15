import os
from dotenv import load_dotenv
load_dotenv()

# optional: set NIDS_IFACE to select interface, else scapy default will be used
IFACE = os.getenv("NIDS_IFACE", None)
BPF_FILTER = os.getenv("NIDS_BPF", None)

# Detection tuning
PORTSCAN_WINDOW_SEC = int(os.getenv("PORTSCAN_WINDOW_SEC", "10"))
PORTSCAN_UNIQUE_PORTS = int(os.getenv("PORTSCAN_UNIQUE_PORTS", "20"))
