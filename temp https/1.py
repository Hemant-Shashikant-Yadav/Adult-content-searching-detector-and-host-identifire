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
    print(f"Packet Number: {packet.number}")

    # Check if the packet has an IP layer
    if 'IP' in packet:
        # Access the sender's IP address (source IP)
        sender_ip = packet.ip.src
        # Access the sender's port
        sender_port = packet[packet.transport_layer].srcport

        # Access the receiver's IP address (destination IP)
        receiver_ip = packet.ip.dst
        # Access the received port
        received_port = packet[packet.transport_layer].dstport

        if sender_ip is not None:
            print("Sender IP:", sender_ip)
        else:
            print("Sender IP not found.")

        if sender_port is not None:
            print("Sender Port:", sender_port)
        else:
            print("Sender Port not found.")

        if receiver_ip is not None:
            print("Receiver IP:", receiver_ip)
        else:
            print("Receiver IP not found.")

        if received_port is not None:
            print("Received Port:", received_port)
        else:
            print("Received Port not found.")
    else:
        print("No IP layer in the packet.")

    # Access the 'tls_handshake_extensions_server_name' attribute
    tls_handshake_extensions_server_name = getattr(packet.layers[3], 'tls_handshake_extensions_server_name', None)

    if tls_handshake_extensions_server_name is not None:
        print("TLS Handshake Extensions Server Name:", tls_handshake_extensions_server_name)
    else:
        print("Value not found for TLS Handshake Extensions Server Name.")

    print("=" * 30)
