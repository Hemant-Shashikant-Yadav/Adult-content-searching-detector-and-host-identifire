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

        # Check if the packet has an IP layer
        # Access the sender's IP address (source IP)
    sender_ip = None
    sender_port = None
    receiver_ip = None
    received_port = None
    if 'IP' in packet:
        sender_ip = packet.ip.src
        # Access the sender's port
        sender_port = packet[packet.transport_layer].srcport

        # Access the receiver's IP address (destination IP)
        receiver_ip = packet.ip.dst
        # Access the received port
        received_port = packet[packet.transport_layer].dstport

    if sender_ip is not None:
        print("Sender IPv4: ", sender_ip)
    else:
        print("Sender IPv6: ", getattr(packet[1], 'addr', None))

    if sender_port is not None:
        print("Sender Port: ", sender_port)
    else:
        print("Sender Port: ", getattr(packet[2], 'srcport', None))

    if receiver_ip is not None:
        print("Receiver IPv4: ", receiver_ip)
    else:
        print("Receiver IPv6: ", getattr(packet[1], 'dst', None))

    if received_port is not None:
        print("Received Port: ", received_port)
    else:
        print("Received Port: ", getattr(packet[2], 'dstport', None))

    print("=" * 30)
