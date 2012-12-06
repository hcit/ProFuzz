#!/usr/bin/env python

# This file is part of ProFuzz.

# ProFuzz is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ProFuzz is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with ProFuzz.  If not, see <http://www.gnu.org/licenses/>.

# Authors: Dmitrijs Solovjovs, Tobias Leitenmaier, Daniel Mayer

from scapy.all import *
from PacketsGenerator import *
import sys
from optparse import OptionParser

global stopSniff
stopSniff=False
global threads
threads=0    

# sends  frames and starts sniffer to find answer
def fuzzerWithSniffer(packetList, interface):
    conf.iface=interface
    thread.start_new_thread(sniffer,(packetList[0].dst,interface))
    
    for packet in packetList:
        sendp(packet)
        continue
        
    global stopSniff
    stopSniff = True
    # wait until sniff thread is ready
    while threads!=0:
        pass
    
def sniffer(filter="", interface="eth2"):
    global threads
    threads=1
    print "sniffing on interface ", interface, " - filtering for ", filter
    snf = sniff(iface=interface, stopper=stopSniffing, stopperTimeout=1)
    pkts = ""
    for x in snf:
        if (filter in str(x.show)): 
        # TODO: adjust filtering: change src with dst
            pkts += str(x.summary)
            pkts += "\n"
    output = open("logs/%s(%s).txt" %(time.strftime("%Y-%m-%d_%H:%M",time.localtime()),filter),  "a")
    output.write(str(pkts))
    output.close()
    threads=0

def stopSniffing():
    return stopSniff

#takes a list of packets and sends containing packets
#catches result via scapy function srp                
def fuzzer(packetList, interface):
    
    conf.iface=interface
    responses = list()
    answered = list()
    unanswered = list()
    
    for packet in packetList:
        responses.append(srp(packet, timeout=1))
    
    for response in responses:
        answered.append(response[0])
        unanswered.append(response[1])
    
    outputAns = open("logs/%s(%s)_answered.txt" %(time.strftime("%Y-%m-%d_%H:%M",time.localtime()),packetList[0].dst),  "a")
    outputUnans = open("logs/%s(%s)_unanswered.txt" %(time.strftime("%Y-%m-%d_%H:%M",time.localtime()),packetList[0].dst),  "a") 
    
    outputAns.write("=== Answered Packets ===\n")
    for a in answered:
        if str(a) != '[]':
            outputAns.write(str(a)+"\n")
    
    outputUnans.write("=== Unanswered Packets ===\n")
    for u in unanswered:
        if str(u) != '[]':
            outputUnans.write(str(u)+"\n")
    
    outputAns.close()
    outputUnans.close()
    
    
def deleteOldLogs():
    files = os.listdir("logs")
    for file in files:
        if(file.find(".txt") != -1):
            os.remove("logs/" + file) #delete old logs

    
if __name__ == '__main__':

    print "\n\nProfinet Fuzzer. Call it like\nFuzzer.py -w false  -s 00:19:99:9d:ed:ab -d 00:1b:1b:17:ba:8a -t pnio -i eth0 -c 10\nor try Fuzzer.py -h for help.\nNeeds Administrator-Rights to send packages!\n\n"

    parser = OptionParser()
    parser.add_option("-t", "--type", dest="frametype", help="Frametype/Protocoltype to send (possible are afr (Alarm Frame Random), afo (Alarm Frames Ordered), pnio (Cyclic RealTime), dcp (DCP Identity Requests), ptcp (Precision Transparent Clock Protocol - BETA")  
    parser.add_option("-s", "--source", dest="sourceMAC", help="Source MAC Address")
    parser.add_option("-d", "--destination", dest="destinationMAC", help="Destination MAC Address (SPS)")
    parser.add_option("-i", "--interface", dest="interface", help="Interface from which to send. For Example: eth0")
    parser.add_option("-c", "--count", dest="count", type="int", help="Number of Frames to send")
    parser.add_option("-w","--sniff", dest="sniff", help="Use sniffing(true or false)")

    (options, args) = parser.parse_args()
    if options.frametype == "afr":
        packets = getRandomAlarmFrames(options.count, options.sourceMAC, options.destinationMAC)
    elif options.frametype == "afo":
        packets = getOrderedAlarmFrames(options.count, options.sourceMAC, options.destinationMAC)
    elif options.frametype == "pnio":
        packets = getRandomPNIOFrames(options.count, options.sourceMAC, options.destinationMAC)
    elif options.frametype == "dcp":
        packets = getRandomDCPIdentityRequests(options.count, options.sourceMAC)
    elif options.frametype == "ptcp":
        packets = getRandomPTCPFrames(options.count, options.sourceMAC)
    else:
        print "protocoltype not found."
        sys.exit()

    print "Fuzzing will start with following parameters:"
    print "Source:\t\t\t",options.sourceMAC
    print "Destination:\t\t",options.destinationMAC
    print "Frametype:\t\t",options.frametype
    print "Number of packets:\t",options.count
    print "Interface:\t\t",options.interface
    print "Sniffing:\t\t",options.sniff
                  
    if(options.sniff==None):
        fuzzer(packets, options.interface)
    elif (options.sniff.lower() == "true"):
        fuzzerWithSniffer(packets, options.interface)
    else:
        fuzzer(packets, options.interface)
    print "Fuzzing finished! See log-folder for responses.."
    
