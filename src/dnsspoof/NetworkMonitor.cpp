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
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>


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

    //struct sniff_ethernet * ethernet = (struct sniff_ethernet*)(packet);
    struct iphdr * ip = (struct iphdr*)(packet + SIZE_ETHERNET);

    //switch the ip now to save us work later

    in_addr_t sa = (in_addr_t)ip->saddr;
    char oldIPSource[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sa, oldIPSource, INET_ADDRSTRLEN);

    in_addr_t da = (in_addr_t)ip->daddr;
    char oldIPDestination[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &da, oldIPDestination, INET_ADDRSTRLEN);

    in_addr_t tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;

    //u_int size_ip = IP_HL(ip) * 4;
    //u_int size_ip = sizeof(*ip) + 2;
    u_int size_ip2 = (ip->ihl & 0xf) * 4;
    u_int size_ip = (ip->ihl) * 4;
    printf("IHL: %d\n", ip->ihl);
    printf("size_ip2: %d\n", size_ip2);
    printf("size_ip: %d\n", size_ip);

    struct udphdr * udp = (struct udphdr *)(packet + SIZE_ETHERNET + size_ip);


    //switch the ports now to save us work later
    int oldDest = ntohs(udp->uh_dport);
    int oldSource = ntohs(udp->uh_sport);
    u_int16_t dest = udp->dest;
    udp->dest = htons(oldSource);
    udp->uh_dport = htons(oldSource);

    udp->source = htons(oldDest);
    udp->uh_sport = htons(oldDest);

    // ^ COULD BE BUGS IN HERE ?


    //u_char * payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);
    //grab the DNS payload out
    struct DNS_HEADER *dns = (struct DNS_HEADER *) (packet + SIZE_ETHERNET + size_ip + sizeof(*udp));
    char *query = (char *)(packet + SIZE_ETHERNET + size_ip + sizeof(*udp) + sizeof(struct DNS_HEADER));

    cout << "---------------------------------------------" << endl;
    cout << "Structures Found Over Packet" << endl;

    cout << "Source IP: " << string(oldIPSource) << endl;
    cout << "Destination IP: " << string(oldIPDestination) << endl;

    cout << "Source Port: " << oldSource << endl;
    cout << "Destination Port: " << oldDest << endl;

    cout << "Transaction ID: " << ntohs(dns->id) << endl;
    cout << "Questions: " << ntohs(dns->q_count) << endl;
    cout << "Answer RRs: " << ntohs(dns->ans_count) << endl;
    cout << "Authority RRs: " << ntohs(dns->auth_count) << endl;
    cout << "Additional RRs: " << ntohs(dns->add_count) << endl;

    cout << "RAW Query Content: " << endl;
    cout << ">" << string(query) << "<" << endl;

    int index = 0;
    QUERY * questionsList = new QUERY[ntohs(dns->q_count)];

    char * ptr = query;
    //Now parse questions out
    for(int i = 0; i < ntohs(dns->q_count); ++i){

        bool keepProcessing = true;
        string queryName = "";
        bool isFirst = true;
        while(keepProcessing){

            int len = (int)(*ptr);
            //cout << "To Read In Segment. Length Is: >" << len << "< Bytes Long" << endl;

            //if this is the first one or the last one. don't put a dot
            if(isFirst || len == 0){
                isFirst = false;
            }else{
                queryName += ".";
            }

            if(len == 0){
                //cout << "Length Is Zero. This Means Were Done" << endl;
                break;
            }else{

                ptr++;
                //char * segment = new char[len];
                //memset(segment, 0, len);
                string segment = "";
                for(int i = 0; i < len; ++i){
                    char c = (*ptr);
                    //cout << "Character Is: >" << c << "<" << endl;
                    segment += c;
                    ptr++;
                }
                //segment[i] = '\0';

                //cout << "Parsed Out Segment Is: >" << segment << "<" << endl;
                queryName += segment;
            }

        }

        ++ptr; // pointer is now looking at header information for question
        struct QUESTION * question = (struct QUESTION *)ptr;
        QUERY * questionQuery = new QUERY;
        questionQuery->name = queryName;
        questionQuery->ques = question;
        questionsList[index++] = (*questionQuery);

        cout << "Full Query Name: " << questionQuery->name << endl;
        cout << "Class " << ntohs(questionQuery->ques->qclass) << endl;
        cout << "Type " << ntohs(questionQuery->ques->qtype) << endl;

        ptr += sizeof(struct QUESTION); //move the pointer past this section

    }

    //switch DNS flags now to save us work later

    cout << "ALL DONE WITH THIS PACKET " << endl;

    cout << "NOW TO SEND THE RESPONSE" << endl;

    //make our repsonse packet. get it ready
    char responsePacket[65536];
    memset(responsePacket, 0, 65536);
    //copy everything we have anyway on the dealio
    memcpy(responsePacket, packet, pkt_info->len);

    //get pointer to the end
    unsigned long addrDif = (const u_char *)ptr - packet;
    char * responsePtr = responsePacket;
    responsePtr += addrDif;







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