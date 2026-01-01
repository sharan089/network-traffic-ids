from scapy.all import sniff

def packet_callback(pkt):
    if pkt.haslayer("IP"):
        print(pkt.summary())

print("Starting packet capture... Press CTRL+C to stop")
sniff(count=5, prn=packet_callback)
