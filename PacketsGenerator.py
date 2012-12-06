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
from ProfinetProtocols import *

def getRandomDCPIdentityRequests(numberOfPackets, srcMac='00:1b:1b:17:ba:8a'):
    
    packetList = list()
    
    ServiceIDs = [0x03, 0x04, 0x05, 0x06] #Get, Set, Identify, Hello
    Options = [0x01, 0x02, 0x03, 0x05, 0x06, 0xff]
    Suboptions = [0x01, 0x02, 0x03, 0x04, 0x05, 0xff]
    
    e = Ether(type=0x8892, src=srcMac, dst='01:0e:cf:00:00:00')
    pnAcyclicRT = ProfinetAcyclicRealTime(FrameID=0xfefe)
    
    i = 0
    while i < numberOfPackets:
       
        dcp = DCPIdentityRequest()
        dcp.ServiceID = random.choice(ServiceIDs)
        dcp.ServiceType=0 #in an request it's always 0
        dcp.Xid=random.randint(1, 4294967294) #just a random number to chain responses together
        dcp.ResponseDelay=random.randint(1, 6400) #response times have to be between 1 and 6400ms
        dcp.DCPDataLength=0x10
        dcp.Option=random.choice(Options)
        dcp.Suboption=random.choice(Suboptions)
        dcp.DCPBlockLength=0xb
        dcp.NameOfStation = random.getrandbits(88)
        
        packetList.append(e/pnAcyclicRT/dcp)
        i = i +1
    return packetList

#returns a list with given number of packets of random valid PNIO-Frames
def getRandomPNIOFrames(numberOfPackets, srcMac='00:19:99:9d:ed:ab', dstMac='00:1b:1b:17:ba:8a'):
    
    packetList = list()
    i = 0
    while i < numberOfPackets:
        #FrameIDs =[0x8000, 0x8061]
        e = Ether(type=0x8892, src=srcMac, dst=dstMac)
        pnio = ProfinetCyclicRealTimeFrame()
        #pnio.FrameID = random.choice(FrameIDs)
        pnio.FrameID = random.randint(0, 65535) #0x0000 - 0xffff
        pnio.Data = random.getrandbits(400)
        pnio.CycleCounter = random.randint(1, 65000)
        pnio.DataStatus = 0x35
        pnio.TransferStatus = 0 #is always 0 in RealTime Communications
        pnio.IOxS = 0x80
        packetList.append(e/pnio)
        
        i = i + 1
        
    return packetList

#returns list with given number of packets of random valid alarm frames
def getRandomAlarmFrames(numberOfPackets, srcMac='00:1b:1b:17:ba:8a', dstMac='00:19:99:9d:ed:ab'):
    
    packetList = list()
    
    FrameIDs = [0xfe01, 0xfc01] #alarm low, alarm high
    Endpoints = [0x8001, 0x0001] #not sure where they come frome..
    PDUTypes=[1,2,3,4] #1=Data,2=NAK,3=ACK,4=ERR
    ErrorCodes = [0x81, 0xcf, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf] #see "britsh standard: fieldbus specifications.pdf" for more info
    ErrorDecodes = [0x80, 0x81]  #PNIORW, PNIO

    e = Ether(type=0x8892, src=srcMac, dst=dstMac)
    
    i = 0
    while i < numberOfPackets:
        
        pnAcyclicRT = ProfinetAcyclicRealTime(FrameID=random.choice(FrameIDs))
        
        pnIOAlarm=ProfinetAlarmFrame()
      
        pnIOAlarm.AlarmDstEndpoint = random.choice(Endpoints)
        pnIOAlarm.AlarmSrcEndpoint = random.choice(Endpoints)
      
        pnIOAlarm.PDUType = random.choice(PDUTypes)
        
        if pnIOAlarm.PDUType == 1:
            pnIOAlarm.AddFlags = 1
        else:
            pnIOAlarm.AddFlags = 0 #when Data, AddFlags = 1, otherwise it's 0 
        
        pnIOAlarm.SendSeqNum = random.randint(32767, 65535) #valid SeqNo Start at 0x7fff. 0xfffe is for sync
        
        if pnIOAlarm.PDUType == 1:
            pnIOAlarm.AckSeqNum = pnIOAlarm.SendSeqNum
        else:
            pnIOAlarm.AckSeqNum = random.randint(32767, 65535) #when Data, AckSeqNum = SendSeqNum. Otherwise it should acknowledge last seqNum
        
        if pnIOAlarm.PDUType == 2 or pnIOAlarm.PDUType == 3:
            pnIOAlarm.VarPartLen = 0
        elif pnIOAlarm.PDUType == 4:
            pnIOAlarm.VarPartLen = 4
        else:
            pnIOAlarm.VarPartLen = random.randint(1, 1432)
        
        pnIOAlarm.ErrorCode = random.choice(ErrorCodes)
        pnIOAlarm.ErrorDecode = random.choice(ErrorDecodes) #this field defines the two following fields
        
        if pnIOAlarm.ErrorDecode == 0x80:
            pnIOAlarm.ErrorCode1 = random.randint(10, 15)
            pnIOAlarm.ErrorCode2 = random.randint(0, 255)
        elif pnIOAlarm.ErrorDecode == 0x81:
            pnIOAlarm.ErrorCode1 = random.randint(1, 78)
            pnIOAlarm.ErrorCode2 = random.randint(1, 255)
    
        packetList.append(e/pnAcyclicRT/pnIOAlarm)
        
        i = i + 1
        
    return packetList


#beta!
def getRandomPTCPFrames(numberOfPackets, srcMac='00:1b:1b:17:ba:8a'):
    
    tlvHeaderTypes=[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x7f]
    e = Ether(type=0x8892, src=srcMac, dst='01:0e:cf:00:00:00')
    pnAcyclicRT = ProfinetAcyclicRealTime(FrameID=0xff40)
    
    packetList = list()

    i = 0
    while i < numberOfPackets:
        ptcp = ProfinetPTCP()
        ptcp.SequenceID=random.randint(1, 65535)
        ptcp.Delay1ns=random.randint(0, 9)
        ptcp.TLVHeader=0x0c00+random.choice(tlvHeaderTypes)
        ptcp.PortMACAddress=random.randint(1, 281474976710655)
        ptcp.TLVHeader2=0x0
        packetList.append(e/pnAcyclicRT/ptcp)
        i = i + 1
    return packetList




#returns a list with ordered (one field after an other, counting upwards values) alarm frames
#since there are infinite possibilities (almost!) theres a parameter to limit the listsize ;)
def getOrderedAlarmFrames(numberOfPackets, srcMac='00:1b:1b:17:ba:8a', dstMac='00:19:99:9d:ed:ab', AlarmDstEndPoint =0x8001, AlarmSrcEndPoint =0x0001):
    
    packetList = list()
    
    FrameIDs = [0xfe01, 0xfc01] #alarm low, alarm high
    PDUTypes=[1,2,3,4] #1=Data,2=NAK,3=ACK,4=ERR
    ErrorCodes = [0x81, 0xcf, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf] #see "britsh standard: fieldbus specifications.pdf" for more info
    ErrorDecodes = [0x80, 0x81]  #PNIORW, PNIO
    
    e = Ether(type=0x8892, src=srcMac, dst=dstMac)
    
    
    pnIOAlarm=ProfinetAlarmFrame()
  
    pnIOAlarm.AlarmDstEndpoint = AlarmDstEndPoint
    pnIOAlarm.AlarmSrcEndpoint = AlarmSrcEndPoint
  
    pnIOAlarm.PDUType = random.choice(PDUTypes)
    for frameid in FrameIDs:
        pnAcyclicRT = ProfinetAcyclicRealTime(FrameID=frameid)
        for pduType in PDUTypes:
            pnIOAlarm.PDUtype=pduType
            if pnIOAlarm.PDUType == 1:
                pnIOAlarm.AddFlags = 1
            else:
                pnIOAlarm.AddFlags = 0 #when Data, AddFlags = 1, otherwise it's 0
            for sendSeqNum in range(32767,65535):
                pnIOAlarm.SendSeqNum=sendSeqNum
                if pnIOAlarm.PDUType == 1:
                    pnIOAlarm.AckSeqNum = pnIOAlarm.SendSeqNum
                    for varPartLen in range(1,1432):
                        pnIOAlarm.VarPartLen = varPartLen
                        for errorCode in ErrorCodes:
                            pnIOAlarm.ErrorCode=errorCode
                            for errorDecode in ErrorDecodes:
                                pnIOAlarm.ErrorDecode=errorDecode
                                if pnIOAlarm.ErrorDecode == 0x80:
                                    for errorCode1 in range(10,15):
                                        pnIOAlarm.ErrorCode1=errorCode1
                                        for errorCode2 in range(0,255):
                                            pnIOAlarm.ErrorCode2=errorCode2
                                            packetList.append(e/pnAcyclicRT/pnIOAlarm)
                                            
                                            if len(packetList) == numberOfPackets:
                                                return packetList
                                            
                                elif pnIOAlarm.ErrorDecode == 0x81:
                                    for errorCode1 in range(1,78):
                                        pnIOAlarm.ErrorCode1=errorCode1
                                        for errorCode2 in range(1,255):
                                            pnIOAlarm.ErrorCode2=errorCode2
                                            packetList.append(e/pnAcyclicRT/pnIOAlarm)
                                            
                                            if len(packetList) == numberOfPackets:
                                                return packetList
                                            
                else:
                    for ackSeqNum in range(32767,65535):
                        pnIOAlarm.AckSeqNum = ackSeqNum #when Data, AckSeqNum = SendSeqNum. Otherwise it should acknowledge last seqNum
                        if pnIOAlarm.PDUType == 2 or pnIOAlarm.PDUType == 3 or pnIOAlarm.PDUType == 4:
                            if pnIOAlarm.PDUType == 2 or pnIOAlarm.PDUType == 3:
                                pnIOAlarm.VarPartLen = 0
                            elif pnIOAlarm.PDUType == 4:
                                pnIOAlarm.VarPartLen = 4
                            for errorCode in ErrorCodes:
                                        pnIOAlarm.ErrorCode=errorCode
                                        for errorDecode in ErrorDecodes:
                                            pnIOAlarm.ErrorDecode=errorDecode
                                            if pnIOAlarm.ErrorDecode == 0x80:
                                                for errorCode1 in range(10,15):
                                                    pnIOAlarm.ErrorCode1=errorCode1
                                                    for errorCode2 in range(0,255):
                                                        pnIOAlarm.ErrorCode2=errorCode2
                                                        packetList.append(e/pnAcyclicRT/pnIOAlarm)
                                                        
                                                        if len(packetList) == numberOfPackets:
                                                            return packetList
                                                        
                                            elif pnIOAlarm.ErrorDecode == 0x81:
                                                for errorCode1 in range(1,78):
                                                    pnIOAlarm.ErrorCode1=errorCode1
                                                    for errorCode2 in range(1,255):
                                                        pnIOAlarm.ErrorCode2=errorCode2
                                                        
                                                        if len(packetList) == numberOfPackets:
                                                            return packetList
