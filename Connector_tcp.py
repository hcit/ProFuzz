import socket
import sys
import getopt
import DataGenerator
import time
import thread
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


usage = sys.argv[0] +' -h <host> -p <port> [-l <length>] [-c <command>]'

def main(argv):
    try:
        opts, args = getopt.getopt(sys.argv[1:],"h:p:l:")
    except getopt.GetoptError, err:
        print usage
        sys.exit(1)
    #check and set arguments
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == "-p":
            port = arg
        elif opt == "-b":
            length = arg
        elif opt == "-c":
            command = arg
             
    #check if values exist
    try:
        host
    except NameError:
        print 'a host is necessary!'
        print usage
        sys.exit(0)
    try:
        port
    except NameError:
        print 'a port is necessary'
        print usage
        sys.exit(0)
    #if there are no length given use random (length=0)
    try:
        length
    except NameError:
        length = 0
        print 'using random length'
    try:
        tcp.connect((host, int(port)))
        print "Connected"
    except socket.error:
            print "Couldn't connect to Server:" + host + ":" + port
            sys.exit(2)
    
    while(True):
        try:
            random = DataGenerator.randString(int(length))
            dataSent = tcp.send(random)
            print "sent"
            time.sleep(5)
            
        except socket.error:
            print "Connection lost..."
                break
    
    
if __name__ == "__main__":
    main(sys.argv[1:])