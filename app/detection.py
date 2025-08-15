"""
detection.py

Usage:
- Import `feed_packet_for_detection(src_ip, dst_port, proto)` and call it from your packet handler.
- It will perform several lightweight checks and insert Detection rows into DB when something is detected.

Assumptions:
- You have `SessionLocal`, `Base` and `models.Detection` defined in `app.database` and `app.models` respectively.
- This file should sit inside the same `app` package as the rest of your backend.
"""

import time
import os
from collections import defaultdict, deque
from threading import Lock, Thread
from datetime import datetime, timedelta

from .database import SessionLocal
from .models import Detection
from .config import (
    PORTSCAN_WINDOW_SEC,
    PORTSCAN_UNIQUE_PORTS,
)

# Detection tuning (override by environment variables if desired)
FLOOD_WINDOW_SEC = int(os.getenv("FLOOD_WINDOW_SEC", "5"))        # seconds window for flood detection
FLOOD_PKT_THRESHOLD = int(os.getenv("FLOOD_PKT_THRESHOLD", "50")) # packets in window considered flood

BLACKLIST_PATH = os.getenv("NIDS_BLACKLIST_PATH", "")  # optional path to newline-separated IPs

# Internal memory structures
_portscan_seen = defaultdict(lambda: deque())  # src_ip -> deque((timestamp, dst_port))
_flood_seen = defaultdict(lambda: deque())     # src_ip -> deque(timestamp)
_lock = Lock()

# Blacklist cache
_blacklist = set()
_blacklist_mtime = 0

def _load_blacklist():
    """Load blacklist IPs from file if provided; caches by mtime."""
    global _blacklist, _blacklist_mtime
    if not BLACKLIST_PATH:
        return
    try:
        mtime = os.path.getmtime(BLACKLIST_PATH)
        if mtime == _blacklist_mtime:
            return
        with open(BLACKLIST_PATH, "r") as f:
            ips = {line.strip() for line in f if line.strip() and not line.startswith("#")}
        _blacklist = ips
        _blacklist_mtime = mtime
    except Exception:
        # ignore errors; blacklist will remain whatever it was
        pass

def _save_detection_db(alert_type: str, src_ip: str, details: str):
    """Persist a detection row to DB (safe to call from threads)."""
    try:
        db = SessionLocal()
        det = Detection(alert_type=alert_type, src_ip=src_ip, details=details, ts=datetime.utcnow())
        db.add(det)
        db.commit()
        db.close()
    except Exception:
        try:
            db.rollback()
            db.close()
        except Exception:
            pass

def _report_detection(alert_type: str, src_ip: str, details: str):
    """Central reporting: persist + (optionally) print/log."""
    # Persist to DB
    _save_detection_db(alert_type, src_ip, details)
    # Print to console for immediate feedback
    ts = datetime.utcnow().isoformat()
    print(f"[DETECTION] {ts} | {alert_type} | {src_ip} | {details}")

def _check_blacklist(src_ip: str):
    """Return True and details if IP is blacklisted."""
    if not src_ip:
        return None
    _load_blacklist()
    if src_ip in _blacklist:
        return f"Source IP {src_ip} matched blacklist"
    return None

def feed_packet_for_detection(src_ip: str, dst_port: int = None, proto: str = None):
    """
    Call this for every parsed packet (lightweight).
    - src_ip: source IP as string
    - dst_port: destination port (int) or None
    - proto: string "TCP"/"UDP"/"ICMP"/...
    Returns: None or detection dict if detection fired (useful for unit tests)
    """
    if not src_ip:
        return None

    now = time.time()
    detected = None

    # 1) Blacklist check (instant)
    bl = _check_blacklist(src_ip)
    if bl:
        _report_detection("Blacklist", src_ip, bl)
        return {"type": "blacklist", "src_ip": src_ip, "details": bl}

    with _lock:
        # 2) Flood detection: count packets from src_ip in last FLOOD_WINDOW_SEC
        dq_f = _flood_seen[src_ip]
        dq_f.append(now)
        # pop older than window
        while dq_f and (now - dq_f[0] > FLOOD_WINDOW_SEC):
            dq_f.popleft()
        if len(dq_f) >= FLOOD_PKT_THRESHOLD:
            details = f"High packet rate: {len(dq_f)} pkts in last {FLOOD_WINDOW_SEC}s"
            _report_detection("Flood", src_ip, details)
            dq_f.clear()
            return {"type": "flood", "src_ip": src_ip, "details": details}

        # 3) Port-scan detection: unique dst ports in window
        if dst_port is not None:
            dq_p = _portscan_seen[src_ip]
            dq_p.append((now, dst_port))
            # pop old
            while dq_p and (now - dq_p[0][0] > PORTSCAN_WINDOW_SEC):
                dq_p.popleft()
            unique_ports = {p for _, p in dq_p}
            if len(unique_ports) >= PORTSCAN_UNIQUE_PORTS:
                details = f"{len(unique_ports)} unique dst ports in last {PORTSCAN_WINDOW_SEC}s"
                _report_detection("Port Scan", src_ip, details)
                dq_p.clear()
                return {"type": "portscan", "src_ip": src_ip, "details": details}

    return None

# Optional helper: periodic maintenance thread to prune old keys for memory control
def _cleanup_loop(interval: int = 60):
    """Background thread that prunes old entries from internal deques."""
    while True:
        time.sleep(interval)
        now = time.time()
        with _lock:
            for src in list(_portscan_seen.keys()):
                dq = _portscan_seen[src]
                while dq and (now - dq[0][0] > PORTSCAN_WINDOW_SEC):
                    dq.popleft()
                if not dq:
                    del _portscan_seen[src]
            for src in list(_flood_seen.keys()):
                dq = _flood_seen[src]
                while dq and (now - dq[0] > FLOOD_WINDOW_SEC):
                    dq.popleft()
                if not dq:
                    del _flood_seen[src]

def start_cleanup_thread():
    t = Thread(target=_cleanup_loop, args=(60,), daemon=True)
    t.start()
