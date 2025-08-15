import threading
from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
from .database import SessionLocal
from .models import Packet
from .detection import feed_packet_for_detection
from .config import IFACE, BPF_FILTER

def _handle_packet(scapy_pkt):
    try:
        ts = datetime.utcnow()
        src_ip = dst_ip = None
        proto = None
        src_port = dst_port = None
        length = int(len(scapy_pkt))
        info = None

        if IP in scapy_pkt:
            ip = scapy_pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            if TCP in scapy_pkt:
                proto = "TCP"
                src_port = int(scapy_pkt[TCP].sport)
                dst_port = int(scapy_pkt[TCP].dport)
                info = f"flags={scapy_pkt[TCP].flags}"
            elif UDP in scapy_pkt:
                proto = "UDP"
                src_port = int(scapy_pkt[UDP].sport)
                dst_port = int(scapy_pkt[UDP].dport)
            elif ICMP in scapy_pkt:
                proto = "ICMP"
                info = f"type={scapy_pkt[ICMP].type} code={scapy_pkt[ICMP].code}"
            else:
                proto = "IP"
        elif IPv6 in scapy_pkt:
            ip6 = scapy_pkt[IPv6]
            src_ip = ip6.src
            dst_ip = ip6.dst
            if TCP in scapy_pkt:
                proto = "TCP"
                src_port = int(scapy_pkt[TCP].sport)
                dst_port = int(scapy_pkt[TCP].dport)
            elif UDP in scapy_pkt:
                proto = "UDP"
                src_port = int(scapy_pkt[UDP].sport)
                dst_port = int(scapy_pkt[UDP].dport)
            else:
                proto = "IPv6"
        else:
            # ignore non-IP packets
            return

        # persist packet
        db = SessionLocal()
        try:
            pkt = Packet(
                ts=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=proto,
                src_port=src_port,
                dst_port=dst_port,
                length=length,
                info=info
            )
            db.add(pkt)
            db.commit()
        finally:
            db.close()

        # detection feeding (lightweight)
        try:
            if proto == "TCP" and src_ip and dst_port:
                feed_packet_for_detection(src_ip, dst_port)
        except Exception:
            pass

    except Exception:
        # ignore packet parsing errors
        pass

class SnifferThread(threading.Thread):
    def __init__(self, iface=None, bpf=None):
        super().__init__(daemon=True)
        self.iface = iface
        self.bpf = bpf

    def run(self):
        sniff(prn=_handle_packet, store=False, iface=self.iface, filter=self.bpf)
