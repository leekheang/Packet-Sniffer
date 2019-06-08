import scapy.all as scapy 

def sniff(interface):
    scapy.sniff(iface=interface, store = False , prn = process_sniffed_packet )
     # store in memory is false  = save memory , prn callback func (call everytime)

def process_sniffed_packet(packet):
    print(packet)

sniff("eth0")