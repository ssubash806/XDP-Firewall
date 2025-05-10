from scapy.all import Ether, IP, TCP, Raw
import base64

eth_layer = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb", type=0x0800)
ip_layer = IP(src="10.0.0.2", dst="192.168.1.1")
tcp_layer = TCP(sport=12345, dport=80, flags="S", seq=1000)
payload = Raw(load="Hello to firewall")

packet = packet = eth_layer / ip_layer / tcp_layer / payload
packet.show2()

raw_bytes = bytes(packet)
encoded_data = base64.b64encode(raw_bytes).decode()

print("Base64 Encoded TCP Packet:")
print(encoded_data)
