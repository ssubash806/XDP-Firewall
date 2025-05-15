from scapy.all import Ether, IP, Raw, UDP, IPv6
import base64

eth_layer = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
#ip_layer = IP(src="10.0.0.2", dst="192.168.1.1")
ip_layer = IPv6(src="2001:db8::2", dst="fd00::1")
udp_layer = UDP(sport=12345, dport=80)
payload = Raw(load="Hello to firewall")

packet = packet = eth_layer / ip_layer / udp_layer / payload
packet.show2()

raw_bytes = bytes(packet)
encoded_data = base64.b64encode(raw_bytes).decode()

print("Base64 Encoded UDP Packet:")
print(encoded_data)
