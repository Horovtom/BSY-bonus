from argparse import ArgumentParser
from dnslib import *
import sys
import socket

class Client:
    def __init__(self, args):
        self.password = args.password
        self.silent = args.silent
        self.listening_port = args.port

        self.__log("Initializing...")
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('', self.listening_port))
        self.__log("Started listening on port: {}".format(self.listening_port))

        self.closed = False

    def __del__(self):
        self.__log("Closing...")
        if self.socket is not None:
            self.socket.close
            self.socket = None
        
    def __log(self, message):
        if self.silent:
            return
        print("CC: {}".format(message))

    def run(self):
        while not self.closed:
            data, addr = self.socket.recvfrom(2048)
            request = DNSRecord.parse(data)

            self.__log("Recieved data: {}, from addr: {}, of type: {}".format(data, addr, request.q.qtype))

            # A6 type:
            if request.q.qtype == 53:
                qname = str(request.q.qname)
                if qname.lower.startswith()







if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-pass", "--password", help="The password used to encrypt the communication", type=str, default="heslo")
    parser.add_argument("-s", "--silent", help="Hide detailed debug info", type=bool, default=False)
    parser.add_argument("-p", "--port", help="Port used to listen for UDP traffic", type=int, default=223) # TODO: CHANGE TO SOMETHING SENSIBLE e.g. 53

    args = parser.parse_args()

    client = Client(args)
    client.run()
