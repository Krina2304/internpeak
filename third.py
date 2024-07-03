import socket
import paramiko
import re

# Function to check SSH version
def check_ssh_version(hostname, port=22):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((hostname, port))
        banner = sock.recv(1024).decode('utf-8').strip()
        sock.close()
        match = re.search(r"SSH-(\d+\.\d+)", banner)
        if match:
            ssh_version = match.group(1)
            return ssh_version
    except Exception as e:
        print(f"Error checking SSH version on {hostname}: {str(e)}")
    return None

# Function to check HTTP version
def check_http_version(hostname, port=80):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((hostname, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        response = sock.recv(1024).decode('utf-8').strip()
        sock.close()
        match = re.search(r"Server: (.+)", response, re.IGNORECASE)
        if match:
            http_version = match.group(1)
            return http_version
    except Exception as e:
        print(f"Error checking HTTP version on {hostname}: {str(e)}")
    return None

if __name__ == "__main__":
    # Example list of hostnames to scan
    hostnames = ["example.com", "192.168.1.1"]

    for hostname in hostnames:
        print(f"Scanning vulnerabilities for {hostname}...")
        
        # Check SSH version
        ssh_version = check_ssh_version(hostname)
        if ssh_version:
            print(f"SSH version: {ssh_version}")
        
        # Check HTTP version
        http_version = check_http_version(hostname)
        if http_version:
            print(f"HTTP version: {http_version}")
        
        print("")
