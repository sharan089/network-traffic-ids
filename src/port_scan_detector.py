from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import datetime

scan_tracker = defaultdict(list)

PORT_THRESHOLD = 3      # low for demo
TIME_WINDOW = 60        # seconds

def log_alert(message):
    with open("logs/alerts.log", "a") as f:
        f.write(message + "\n")

def detect_scan(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        tcp = pkt[TCP]

        # SYN flag (Windows-safe)
        if tcp.flags & 0x02:
            src_ip = pkt[IP].src
            dst_port = tcp.dport
            now = time.time()

            scan_tracker[src_ip].append((dst_port, now))

            # Keep only recent entries
            scan_tracker[src_ip] = [
                (p, t) for p, t in scan_tracker[src_ip]
                if now - t <= TIME_WINDOW
            ]

            ports = set(p for p, _ in scan_tracker[src_ip])

            if len(ports) >= PORT_THRESHOLD:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert_msg = (
                    f"[{timestamp}] PORT SCAN DETECTED | "
                    f"Source={src_ip} | Ports={ports}"
                )

                print(alert_msg)
                log_alert(alert_msg)
                scan_tracker[src_ip].clear()

print("IDS running... waiting for TCP SYN packets")
sniff(filter="tcp", prn=detect_scan, store=False)
