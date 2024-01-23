from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest, TCP
from colorama import init, Fore


init()

red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
reset = Fore.RESET

def sniff_packets(iface):
    if iface:
        sniff(prn = process_packet, iface = iface, store=False)
    else:
        sniff(prn = process_packet, store= False)
def process_packet(packet):
    
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        src_port = packet[TCP].dport
        
        print(f"{blue}[+] {src_ip} is using port {src_port} to connect to {dst_ip} at port {dst_port}")

sniff_packets('eth0')

