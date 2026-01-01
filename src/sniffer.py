from scapy.all import sniff, IP, TCP

def handle_packet(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        print(pkt.summary())

print("Sniffing TCP packets... Press CTRL+C to stop")
sniff(filter="tcp", prn=handle_packet)
