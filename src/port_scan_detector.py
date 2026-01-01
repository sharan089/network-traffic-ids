from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

scan_tracker = defaultdict(list)

PORT_THRESHOLD = 3      # VERY LOW (guaranteed)
TIME_WINDOW = 60        # seconds

def detect_scan(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        tcp = pkt[TCP]

        # Check SYN flag (numeric, Windows-safe)
        if tcp.flags & 2:
            src_ip = pkt[IP].src
            dst_port = tcp.dport
            now = time.time()

            scan_tracker[src_ip].append((dst_port, now))

            # Keep only recent entries
            scan_tracker[src_ip] = [
                (p, t) for p, t in scan_tracker[src_ip]
                if now - t <= TIME_WINDOW
            ]

            if len(set(p for p, _ in scan_tracker[src_ip])) >= PORT_THRESHOLD:
                print("\n[ALERT] PORT SCAN DETECTED")
                print("Source IP :", src_ip)
                print("Ports     :", set(p for p, _ in scan_tracker[src_ip]))
                scan_tracker[src_ip].clear()

print("IDS running... waiting for TCP SYN packets")
sniff(filter="tcp", prn=detect_scan, store=False)

