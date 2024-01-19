import pyshark


def filter_http_traffic_file(packet):
    """
    This function is designed to parse all the Hypertext Transfer Protocol (HTTP)
    packets from a Packet Capture (PCAP) file.

    :param packet: raw packet from a pcap file
    :return: specific packet details or None if attributes are missing
    """
    transport_layer = packet.transport_layer

    # Check if the packet has a transport layer and the necessary attributes
    if transport_layer and hasattr(packet, transport_layer):
        dst_port = getattr(packet[transport_layer], 'dstport', None)

        # Check if the destination port is '80' (assuming HTTP is running on the default port)
        if dst_port == '80':
            results = get_packet_details(packet)
            return results


def get_packet_details(packet):
    """
    This function is designed to parse specific details from an individual packet.

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
        uri = getattr(packet.http, 'request_uri', None)
    else:
        uri = None

    return f'Packet Timestamp: {packet_time}' \
           f'\nProtocol type: {transport_layer}' \
           f'\nSource address: {source_address}' \
           f'\nSource port: {source_port}' \
           f'\nDestination address: {destination_address}' \
           f'\nDestination port: {destination_port}' \
           f'\nURI: {uri}\n'


def get_file_captures(parse_type, pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    for raw_packet in capture:
        if parse_type == 'http':
            results = filter_http_traffic_file(raw_packet)
            if results is not None:
                print(results)


pcap_file = 'http.pcap'
get_file_captures('http', pcap_file)
