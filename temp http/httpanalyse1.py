import pyshark




pcap_file = '/ADCET HACKATHON/1.pcap'

capture = pyshark.FileCapture(pcap_file)

print(capture[84666])
# print(capture[0])

