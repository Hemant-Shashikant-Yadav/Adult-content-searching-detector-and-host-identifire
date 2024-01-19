import pyshark


def extract_packets_from_pcap(pcap_file):
    captured = pyshark.FileCapture(pcap_file, display_filter="http.host")
    full_packets = []

    for packet in captured:
        full_packets.append(packet)

    return full_packets


pcap_file = "http.pcap"
full_packets = extract_packets_from_pcap(pcap_file)

for packet in full_packets:
    url = getattr(packet[3], 'referer', None)
    if url is not None:
        print(f"Packet Number: {packet.number}")
        print("Fetched HTTP url : ", url)
    else:
        continue

    print("Sender IP: ", getattr(packet[1], 'addr', None))
    print("Received Port: ", getattr(packet[2], 'srcport', None))

    print("Receiver IPv6: ", getattr(packet[1], 'dst', None))

    print("Received Port: ", getattr(packet[2], 'dstport', None))

    print("=" * 30)
