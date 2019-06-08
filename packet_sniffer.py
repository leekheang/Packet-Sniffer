import scapy.all as scapy 
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store = False , prn = process_sniffed_packet )
     # store in memory is false  = save memory , prn callback func (call everytime)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
         print(packet)

sniff("wlp7s0")