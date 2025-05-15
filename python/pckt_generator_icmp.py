from scapy.all import Ether, IP, ICMP, Raw, IPv6, ICMPv6EchoRequest
import base64

eth_layer = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
#ip_layer = IP(src="10.0.0.5", dst="192.168.1.1")
ip_layer = IPv6(src="2001:db8::5", dst="fd00::1")
#icmp_layer = ICMP(type=8, code=0)
icmp_layer = ICMPv6EchoRequest()
payload = Raw(load="Ping test to firewall")

packet = eth_layer / ip_layer / icmp_layer / payload
packet.show2()

raw_bytes = bytes(packet)
encoded_data = base64.b64encode(raw_bytes).decode()

print("\nBase64 Encoded ICMP Packet:")
print(encoded_data)
