from detection import detect_port_scan
from database import SessionLocal
import time

def process_packet(packet):
    db = SessionLocal()
    # Pehle packet ko store karo
    # ... existing code to store packet ...

    # Har 10 second me detection check
    if int(time.time()) % 10 == 0:
        detect_port_scan(db)

    db.close()
