import scapy.all as scapy
import re

# Function to analyze packets and detect port scanning
def analyze_packet(packet):
    # Check if the packet is an ICMP packet (ping scan)
    if packet.haslayer(scapy.ICMP):
        icmp_type = packet[scapy.ICMP].type
        if icmp_type == 8:
            return "Possible ICMP ping scan detected"
    
    # Check if the packet is a TCP packet (port scan)
    if packet.haslayer(scapy.TCP):
        tcp_flags = packet[scapy.TCP].flags
        
        # SYN scan detection (SYN packet with no ACK)
        if tcp_flags == 2:
            return "Possible SYN scan detected"
        
        # XMAS scan detection (TCP packet with unusual flags set)
        if tcp_flags == 41:  # Flags: URG + FIN + PSH
            return "Possible XMAS scan detected"
        
        # NULL scan detection (TCP packet with no flags set)
        if tcp_flags == 0:
            return "Possible NULL scan detected"
    
    return None

# Function to start the IDS
def start_ids():
    print("Starting IDS (Intrusion Detection System)...")
    try:
        scapy.sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("IDS stopped.")

# Function to process each packet captured by scapy
def process_packet(packet):
    result = analyze_packet(packet)
    if result:
        print(f"Alert: {result} from {packet[scapy.IP].src}")

if __name__ == "__main__":
    # Start the IDS
    start_ids()
