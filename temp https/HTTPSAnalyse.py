import pyshark


def filter_https_traffic_file(packet):
    """
    This function is designed to parse Hypertext Transfer Protocol Secure (HTTPS) packets
    from a Packet Capture (PCAP) file.

    :param packet: raw packet from a pcap file
    :return: specific packet details or None if attributes are missing
    """
    transport_layer = packet.transport_layer

    # Check if the packet has a transport layer and the necessary attributes
    if transport_layer and hasattr(packet, transport_layer):
        dst_port = getattr(packet[transport_layer], 'dstport', None)

        # Check if the destination port is '443' (HTTPS)
        if dst_port == '443':
            results = get_packet_details(packet)
            return results


def get_packet_details(packet):
    """
    This function is designed to parse specific details from an individual HTTPS packet.

    :param packet: raw packet from either a pcap file or via live capture using TShark
    :return: specific packet details
    """
    transport_layer = packet.transport_layer

    # Check if the packet has an IP layer
    if hasattr(packet, 'ip'):
        source_address = getattr(packet.ip, 'src', None)
        destination_address = getattr(packet.ip, 'dst', None)
    else:
        source_address = None
        destination_address = None

    # Extract details based on the transport layer protocol
    source_port = getattr(packet[transport_layer], 'srcport', None)
    destination_port = getattr(packet[transport_layer], 'dstport', None)
    packet_time = packet.sniff_time

    # Check if the packet has an HTTP layer
    if hasattr(packet, 'http'):
        host = getattr(packet.http, 'host', None)
        uri = getattr(packet.http, 'request_uri', None)
        full_url = f'Request URI: {uri}, Host: {host}' if uri and host else None
    else:
        host = None
        full_url = None

    return f'Packet Timestamp: {packet_time}' \
           f'\nProtocol type: {transport_layer}' \
           f'\nSource address: {source_address}' \
           f'\nSource port: {source_port}' \
           f'\nDestination address: {destination_address}' \
           f'\nDestination port: {destination_port}' \
           f'\nHost: {host}' \
           f'\nFull URL: {full_url}\n'


def get_https_captures(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    for raw_packet in capture:
        results = filter_https_traffic_file(raw_packet)
        if results is not None:
            print(results)


pcap_file = '/ADCET HACKATHON/2.pcap'
get_https_captures(pcap_file)
