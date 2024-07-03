import scapy.all as scapy
import socket

# Function to discover devices in the network using ARP requests
def discover_devices(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcasting to all devices in the network
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return devices

# Function to scan open ports on a specific IP address using TCP SYN packets
def scan_ports(ip):
    open_ports = []
    for port in range(1, 1025):  # Scan common ports range
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

if __name__ == "__main__":
    # Discover devices in the network
    ip_range = "192.168.1.0/24"  # Example IP range, modify as per your network
    devices = discover_devices(ip_range)
    
    print("Devices discovered:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
        
        # Scan open ports for each discovered device
        open_ports = scan_ports(device['ip'])
        if open_ports:
            print(f"   Open ports: {open_ports}")
        else:
            print("   No open ports found.")
        print("")
