import os
import sys
from scapy.all import *

# Disclaimer and terms of use
print("------------------------ Packet Sniffer Tool Disclaimer ---------------------------")
print("By using this tool, you agree to the following terms and conditions:")
print("\n1. You will only use this tool on networks and systems for which you have explicit permission.")
print("2. You will not use this tool to violate any laws, regulations, or terms of service.")
print("3. You will not use this tool to harm, disrupt, or exploit any networks or systems.")
print("4. You will not use this tool to intercept, collect, or store any sensitive or confidential information.")

accept_terms = input("\nDo you accept these terms and conditions? (y/n): ")

if accept_terms.lower() != 'y':
    print("You must accept the terms and conditions before using this tool.")
    sys.exit()

print("\n--------------- Packet Sniffing Tool ---------------")

# Defines a function to display and save the captured packets
def packet_sniff(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = packet[IP].proto
        payload = str(packet[TCP].payload)

        output_string = f"Source IP: {src_ip}\n"
        output_string += f"Destination IP: {dst_ip}\n"
        output_string += f"Source Port: {src_port}\n"
        output_string += f"Destination Port: {dst_port}\n"
        output_string += f"Protocol: {protocol}\n"
        output_string += f"Payload: {payload[:50]}...\n"

        print(output_string, end='')
        with open('packet_sniffer_result.txt', 'a') as f:
            f.write(output_string)

# Sets the path and filename for the output text file
output_file = "packet_sniffer_result.txt"

# Calls the sniff() function from the Scapy library to capture and analyze network packets
sniff(filter="tcp", prn=packet_sniff, store=0, count=10)

# Displays the output file's name and location after successful sniffing
print(f"\nResults saved to: {output_file}")
