from argparse import ArgumentParser
from dnslib import *
import sys
import socket


class Server:
    def __init__(self, args):
        self.password = args.password
        self.verbose = args.verbose
        self.listening_port = args.port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('', self.listening_port))
        self.log("Started listening on port: {}".format(self.listening_port))

        
    def log(self, message):
        if not self.verbose:
            return
        print("CC: {}".format(message))



if __name__ == '__main__':
    parser = ArguemntParser()
    parser.add_argument("-s", "--password", help="The password used to encrypt the communication")
    parser.add_argument("-v", "--verbose", help="Show detailed debug info")
    parser.add_argument("-p", "--port", help="Port used to listen for UDP traffic")

    args = parser.parse_args()

    client = Client(args)
    while not client.closed():
        client.tick()
