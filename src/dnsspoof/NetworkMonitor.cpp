//
// Created by bensoer on 18/10/16.
//

#include "NetworkMonitor.h"
#include "Logger.h"
#include "Structures.h"
#include <netinet/udp.h>
#include <netinet/in.h>
#include <iostream>
#include <zconf.h>
#include <dnet.h>
#include <cstring>

/**
 * instance is the instance stored in the network monitor of the netowrk monirot. This is used to enforce a singleton
 * structure
 */
NetworkMonitor * NetworkMonitor::instance = nullptr;

NetworkMonitor::NetworkMonitor() {

}

/**
 * getInstance is a method that generates a new instance of the NetworkMonitor if one does not exist. Otherwise it
 * returns the already created instance. This is used to enforce the singleton structure
 * @return NetworkMonitor - a new or existing instance of the NetworkMontior
 */
NetworkMonitor * NetworkMonitor::getInstance() {
    if(NetworkMonitor::instance == nullptr){
        NetworkMonitor::instance = new NetworkMonitor();
    }

    return NetworkMonitor::instance;
}

void NetworkMonitor::setFilter(string filter) {
    this->filter = filter;
}

/**
 * packetCallback is a statis processing method that is used by libpcap to handle matching packets from the filter.This
 * method parses apart the packet and fetches the data from it. This data is then set and libpcap is stopped so that the
 * command can be processed and replied to.
 * @param ptrnull
 * @param pkt_info
 * @param packet
 */
void NetworkMonitor::packetCallback(u_char* ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet){

    Logger::debug("Packet Found. Now Parsing");

    struct sniff_ethernet * ethernet = (struct sniff_ethernet*)(packet);
    struct sniff_ip * ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    //u_int size_ip = IP_HL(ip) * 4;
    u_int size_ip = sizeof(*ip) + 2;
    struct udphdr * udp = (struct udphdr *)(packet + SIZE_ETHERNET + size_ip);

    //u_char * payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);
    //grab the DNS payload out
    struct DNS_HEADER *dns = (struct DNS_HEADER *) (packet + SIZE_ETHERNET + size_ip + sizeof(*udp));
    char *query = (char *)(packet + SIZE_ETHERNET + size_ip + sizeof(*udp) + sizeof(*dns));

    cout << "Structures Found Over Packet" << endl;
    //check if it is our packet - has dest port of 4378
    short destinationPort = ntohs(udp->dest);
    cout << "Destination Port: " << destinationPort << endl;
    cout << "RAW Query Content: " << endl;
    cout << string(query) << endl;

    //NetworkMonitor::instance->killListening();

}

/**
 * killListening is a helepr method so that the client can tell the NetworkMontior and libpcap to stop listening for
 * packets
 */
void NetworkMonitor::killListening() {
    if(this->currentFD != nullptr){
        pcap_breakloop(this->currentFD);
    }
}

/**
 * listenForTraffic is the main functionality method of the NetworkMonitor. This function takes the passed in listening
 * interface and using the configuration filter, configured libpcap to start listening for packets on the interface. The
 * NetworkMonitor::packetCallback is then called as each packet is found that matches the filter
 * @param listeningInterface pcap_if_t - The interface to listen for packets on
 * @return String - The parsed command that has been received from the network
 */
string NetworkMonitor::listenForTraffic(pcap_if_t * listeningInterface) {

    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 subnetMask;
    bpf_u_int32 ip;

    //fetch network information for interface
    pcap_lookupnet(listeningInterface->name, &subnetMask, &ip, errbuf);

    //open up a raw socket and listen in promisc mode on it for data

    if((this->currentFD = pcap_open_live(listeningInterface->name, BUFSIZ, 1, -1, errbuf)) == NULL){
        Logger::error("NetworkMonitor:listenForTraffic - There Was An Error in pcap_open_live");
        Logger::error(string(errbuf));
        return "-1";
    }

    //setup the libpcap filter
    struct bpf_program fp;
    //compile the filter
    if(pcap_compile(this->currentFD, &fp, this->filter.c_str(), 0, ip) == -1){
        Logger::error("NetworkMonitor:listenForTraffic - There Was An Error Compiling The Filter");
        return "-1";
    }
    //set the filter
    if(pcap_setfilter(this->currentFD, &fp) == -1){
        Logger::error("NetworkMonitor:listenForTraffic - There Was An Error Setting The Filter");
        return "-1";
    }

    u_char* args = NULL;
    //listen for UDP packets
    pcap_loop(this->currentFD, 0, NetworkMonitor::packetCallback, args);

    if(this->data == nullptr){
        return "";
    }else{
        return (*this->data);
    }

}