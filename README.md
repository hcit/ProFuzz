# ProFuzz

Simple PROFINET fuzzer based on Scapy <http://www.secdev.org/projects/scapy/> (2.1.0)

To workaround some problems with Scapy, the file "sendrecv.py" has to be replaced
with the one in the repository.


## Dependencies

- tcpdump 
- graphviz 
- imagemagick 
- python-gnuplot 
- python-crypto 
- python-pyx

# Authors

- Dmitrijs Solovjovs
- Tobias Leitenmaier
- Daniel Mayer

- Supervisor: <roland.koch@hs-augsburg.de>

# Project

This project was a student project at the [University of Applied Sciences Augsburg](http://www.hs-augsburg.de)
in SS12.

It allows the fuzzing of some PROFINET frames. The following frames are implemented:

- afr (Alarm Frame Random)
- afo (Alarm Frames Ordered)
- pnio (Cyclic RealTime)
- dcp (DCP Identity Requests)
- ptcp (Precision Transparent Clock Protocol - BETA)



## Example for running the fuzzer

sudo python Fuzzer.py -w false  -s 00:19:99:9d:ed:ab -d 00:1b:1b:17:ba:8a -t dcp  -i eth2 -c 100

### Explanation

- -s -> Source MAC
- -d -> Destination MAC 
- -t one of the scan types mentioned above
- -i, "--interface" -> Interface from which to send. For Example: eth0
- -c, "--count" -> number of Frames to send
- -w,"--sniff" -> use sniffing(true or false) (should be false)

# Questions

If you have any other questions, feel free to contact me at <roland.koch@hs-augsburg.de>

