#8505-a4-dnsspoof
A DNS Spoofing Program. Cuz rerouting your frenemies was a passtime of dreams

#Setup
#Prerequisites
In order for this application to work a number of tools need to be available on your system. You will need
Python3, g++ and cmake. In addition to these tools, you will need a number of uncommon libraries installed on
your python and g++ system.
* scappy for Python3 - `pip3 install scapy-python3`
* libdnet for g++ - `dnf install libndet-devel` for REHL systems
* libpcap library of some kind


#Installation
Execute the following from the project root

1. `cd` to the `src` folder
2. Execute `cmake .`
3. Execute `make`
4. The compiled DNS Spoofer will be in the the project root under the `bin` folder
5. The Arp Poison program is available from the project root under `src/arppoison/arppoison.py` and requires
no pre-compilation

#Usage
Startup each program with no parameters to view a full breakdown of all command line options. You can start each program
with the following commands:

For `arppoison.py` from within the `src/arpoison` folder:
```
sudo python3 arpposion.py
```
For `8505_a4_dnsspoof` within the compiled `bin` folder:
```
sudo ./8505_a4_dnsspoof
```