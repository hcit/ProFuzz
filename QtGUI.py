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


from PyQt4 import QtCore, QtGui, uic
from Fuzzer import *
from PacketsGenerator import *
import os, sys
import subprocess
import signal
from multiprocessing import Process

class gui(QtGui.QDialog):
    # constructor
    def __init__(self):
        QtGui.QDialog.__init__(self)

        # Set up the user interface from Designer
        self.ui = uic.loadUi('gui.ui')

        # Insert Interfaces into Combobox
        interfaces = self.getInterfaces()
        for iface in interfaces:
            self.ui.interfaceBox.addItem(iface)
        
        self.ui.show()
        
        # Connect the buttons
        self.connect(self.ui.startButton, QtCore.SIGNAL('clicked()'), self.startFuzzing)
        self.connect(self.ui.stopButton, QtCore.SIGNAL('clicked()'), self.stopFuzzing)
        self.connect(self.ui.showLogsButton, QtCore.SIGNAL('clicked()'), self.showLogs)
        self.connect(self.ui.actionAbout, QtCore.SIGNAL('triggered()'), self.showAbout)

    def showLogs(self):
        subprocess.Popen(['xdg-open', self.ui.logsPath.text()])
        
    def showAbout(self):
        self.ui.status.setText("Dev by HSA-Students")

    # start Fuzzing
    def startFuzzing(self):
        interface = str(self.ui.interfaceBox.currentText())
        packetCount = int(self.ui.packetSlider.value())
        sourceMac = str(self.ui.srcMac.text())
        destMac = str(self.ui.dstMac.text())
        proto = str(self.getProto())
        if proto == "afr":
            packets = getRandomAlarmFrames(packetCount, sourceMac,destMac)
        elif proto == "afo":
            packets = getOrderedAlarmFrames(packetCount, sourceMac, destMac)
        elif proto == "pnio":
            packets = getRandomPNIOFrames(packetCount, sourceMac, destMac)
        elif proto == "dcp":
            packets = getRandomDCPIdentityRequests(packetCount, sourceMac)
        elif proto == "ptcp":
            packets = getRandomPTCPFrames(packetCount, sourceMac)
        if len(proto) > 1:
            if(self.ui.sniffing.isChecked()==True):
                self.p = Process(target=fuzzerWithSniffer, args=(packets, interface))
                self.p.start()
            else:
                self.p = Process(target=fuzzer, args=(packets, interface))
                self.p.start()
        else:
            self.ui.status.setText("No Protocol!")
        

    # stop Fuzzing
    def stopFuzzing(self):
        os.kill(self.p.pid, signal.SIGTERM)
        print "stop now!"

    def getInterfaces(self):
        interfaces = []
        # read the file /proc/net/dev only in Linux
        f = open('/proc/net/dev','r')

        # put the content to list
        ifacelist = f.read().split('\n')

        # close the file
        f.close()

        # remove 2 lines header
        ifacelist.pop(0)
        ifacelist.pop(0)

        # loop to check each line
        for line in ifacelist:
            ifacedata = line.replace(' ','').split(':')
            # check the data have 2 elements
            if len(ifacedata) == 2:
                # check the interface is up (Transmit/Receive data)
                if int(ifacedata[1]) > 0:
                    # print the interface
                    interfaces.append(ifacedata[0])
        return interfaces

    def getProto(self):
        proto = ""
        # chose checked RadioButton
        if self.ui.radioButton.isChecked():
            proto = "afr"
        elif self.ui.radioButton_2.isChecked():
            proto = "afo"
        elif self.ui.radioButton_3.isChecked():
            proto = "pnio"
        elif self.ui.radioButton_4.isChecked():
            proto = "dcp"
        elif self.ui.radioButton_5.isChecked():
            proto = "ptcp"
            
        return proto

if __name__ == '__main__':
    import sys
    app = QtGui.QApplication(sys.argv)
    ui = gui()
    sys.exit(app.exec_())
