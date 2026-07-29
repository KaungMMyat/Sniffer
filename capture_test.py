from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    
    if IP not in packet:           
        return
    
    protocol = "Unknown"
    
    if TCP in packet:
        protocol = "TCP"
        
    elif UDP in packet:
        protocol = "UDP"
        
    elif ICMP in packet:
        protocol = "ICMP"

    print(f"Protocol: {protocol}")
    print(f"Source: {packet[IP].src}")
    print(f"Destination: {packet[IP].dst}")
    print("-" * 40)

sniff(
    prn=packet_callback,    # prn means "Run this function for every captured packet".
    
    #iface = "Wi-Fi",       # specify the interface to capture packets from
    #filter = "ip",         # capture only IP packets [BPF (Berkeley Packet Filter) expression]
    #store = False
    #count = 10             # capture only 10 packets
    #timeout = 10           # timeout after 10 seconds
)