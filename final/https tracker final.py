import pyshark


def extract_packets_from_pcap(pcap_file):
    captured = pyshark.FileCapture(pcap_file, display_filter="tls.handshake.type eq 1")
    full_packets = []

    for packet in captured:
        full_packets.append(packet)

    return full_packets


pcap_file = "2.pcap"
full_packets = extract_packets_from_pcap(pcap_file)

for packet in full_packets:
    tls_handshake_extensions_server_name = getattr(packet.layers[3], 'tls_handshake_extensions_server_name', None)

    if tls_handshake_extensions_server_name is not None:
        print(f"Packet Number: {packet.number}")
        print("TLS Handshake Extensions Server Name:", tls_handshake_extensions_server_name)
    else:
        continue

    print("Sender IP: ", getattr(packet[1], 'addr', None))

    print("Sender Port: ", getattr(packet[2], 'srcport', None))

    print("Receiver IP: ", getattr(packet[1], 'dst', None))

    print("Received Port: ", getattr(packet[2], 'dstport', None))

    print("=" * 30)
