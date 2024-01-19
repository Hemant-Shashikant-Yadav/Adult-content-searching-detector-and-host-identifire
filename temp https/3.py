import pyshark
import xml.etree.ElementTree as ET

def extract_packets_from_pcap(pcap_file):
    captured = pyshark.FileCapture(pcap_file, display_filter="tls.handshake.type eq 1")
    full_packets = []

    for packet in captured:
        full_packets.append(packet)

    return full_packets

pcap_file = "Y:\Coding\Python-1\ADCET HACKATHON\\final\\t2.pcap"
full_packets = extract_packets_from_pcap(pcap_file)

a = full_packets
print(len(a))
b = a[27][3]

print(type(b))
print(dir(b))
# Assuming b is an instance of XmlLayer
# Print the attributes and methods of the XmlLayer object

# Access the 'tls_handshake_extensions_server_name' attribute
tls_handshake_extensions_server_name = getattr(b, 'handshake_extensions_server_name', None)

if tls_handshake_extensions_server_name is not None:
    print(" Name:", tls_handshake_extensions_server_name)
else:
    print("Value not found for Name.")