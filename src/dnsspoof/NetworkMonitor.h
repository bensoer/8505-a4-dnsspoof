//
// Created by bensoer on 18/10/16.
//

#ifndef INC_8505_A4_DNSSPOOF_NETWORKMONITOR_H
#define INC_8505_A4_DNSSPOOF_NETWORKMONITOR_H

#include <string>
#include <pcap.h>

using namespace std;

class NetworkMonitor {

private:
    NetworkMonitor();
    static NetworkMonitor * instance;
    pcap_t * currentFD = nullptr;
    string * data = nullptr;
    string filter = "udp dst port 100";

    int rawSocket;

    unsigned short csum(unsigned short *ptr, int nbytes);

    static void packetCallback(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, const u_char *packet);

public:
    static NetworkMonitor * getInstance();

    string listenForTraffic(pcap_if_t * listeningInterface);

    void killListening();

    void setFilter(string filter);


};


#endif //INC_8505_A4_DNSSPOOF_NETWORKMONITOR_H
