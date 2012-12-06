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


#Profinet Precision Transparent Clock Protocol
class ProfinetPTCP(Packet):
    name = "Profinet Precision Transparent Clock Protcol"
    fields_desc=[ BitFieldLenField("Padding", 0, 96), #12 bytes padding
                 XShortField("SequenceID", None),
                 XShortField("Padding2", 0), #2 bytes padding
                 XIntField("Delay1ns", None),
                 XShortField("TLVHeader", None),
                 BitFieldLenField("PortMACAddress", None, 48),
                 XShortField("TLVHeader2", None)]

#in an identity request the destination mac has to be Multicast (01-0e-cf-00-00-00)!
class DCPIdentityRequest(Packet):
    name = "DCP Identity Request"
    fields_desc=[ XByteField("ServiceID", 5), #5=Identify
                 XByteField("ServiceType", None),
                 XIntField("Xid", None),
                 XShortField("ResponseDelay", None),
                 XShortField("DCPDataLength", None),
                 XByteField("Option", None), #2=Device Properties
                 XByteField("Suboption", None), #2=Name of Station
                 XShortField("DCPBlockLength", 0x0b), #gives length of following field
                 BitFieldLenField("NameOfStation", None, 88), #fix for 11 characters
                 XByteField("Padding", 0)]

class writeRequest(Packet):
    name = "Profinet IO Write Request"
    fields_desc=[ ByteField("VLAN", 4),
                 XByteField("Ethertype",0x0800),
                 ShortField("IPUDP", 28),
                 ByteField("RPC", 80),
                 ByteField("NDR", 20),
                 ByteField("WriteBlock", 64),
                 ByteField("WriteData", None),
                 ByteField("FCS", 4)  ]

#RT_CLASS_1 Frame: Unsynchronized communication within one subnet
class ProfinetAcyclicRealTime(Packet):
    name = "Profinet Acyclic Real-Time"
    fields_desc=[ XShortField("FrameID", 0xff40)]


#RT_CLASS_2 Frame: Synchronized communication within one subnet
#ProfinetCyclicRealTimeFrame has to be after Ether-Frame
class ProfinetCyclicRealTimeFrame(Packet):
    name = "Profinet Real-Time-Frame"
    fields_desc=[ XShortField("FrameID", 0x0), #0x8000 (SPS) or 0x8061 (robot)
                XByteField("IOxS", 0x80), #good
                BitFieldLenField("Data", 0, 400), #a 51 bytes field for Data
                ShortField("CycleCounter", 0),
                XByteField("DataStatus", 0x35),  #0x35: Valid and Primary, OK and Run
                XByteField("TransferStatus", 0x00) ] #ok
            
		
#ProfinetAlarmFrame has to be after Ether-Frame and ProfinetAcyclicRealTime-Frame
class ProfinetAlarmFrame(Packet):
    name = "Profinet Alarm Frame"
    fields_desc=[ XShortField("AlarmDstEndpoint", None),
                XShortField("AlarmSrcEndpoint", None),
                XByteField("PDUType", None),
                XByteField("AddFlags", None),
                XShortField("SendSeqNum", None),
                XShortField("AckSeqNum", None),
                XShortField("VarPartLen", None),
                XByteField("ErrorCode", None),
                XByteField("ErrorDecode", None),
                XByteField("ErrorCode1", None),
                XByteField("ErrorCode2", None) ]
    
