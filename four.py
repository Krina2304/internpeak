import scapy.all as scapy

# Function to sniff packets
def packet_sniffer():
    try:
        # Sniffing packets on the default network interface (change iface as needed)
        scapy.sniff(iface="eth0", store=False, prn=process_packet)
    except KeyboardInterrupt:
        print("Packet sniffing stopped.")

# Function to process each captured packet
def process_packet(packet):
    try:
        # Print the packet summary
        print(packet.summary())
        
        # Uncomment the line below to print the full packet details
        # print(packet.show())
        
    except Exception as e:
        print(f"Error processing packet: {str(e)}")

if __name__ == "__main__":
    print("Starting packet sniffer...")
    packet_sniffer()
