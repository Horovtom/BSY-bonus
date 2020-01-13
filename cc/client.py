from argparse import ArgumentParser
import dns.resolver
import sys


class Client:
    def __init__(self, args):
        self.password = args.password
        self.silent = args.silent
        self.server_port = args.port
        self.server_ip = args.destination

        self.__log("Initializing...")

        self.sender = dns.resolver.Resolver()
        self.sender.nameservers = [self.server_ip]
        self.sender.nameserver_ports = {self.server_ip, self.server_port}

        self.__log("Initialized DNS sender with nameserver: {}".format(self.sender.nameserver_ports))

        self.running = False

    def __del__(self):
        self.__log("Closing...")

    def __log(self, message):
        if self.silent:
            return
        print("CC: {}".format(message))

    def server_reachable(self):
        """
        Initializes communication with the server.
        """

        try:
            # Initialize by sending a regular google.com request to the server:
            answer = self.sender.query("google.com", "A")

            if not answer.response.answer[0].items[0].address == "1.2.3.4":
                return False

            # If we get 1.2.3.4 as an answer, we should start sending hearthbeats.
            return True
        except Exception:
            return False

    def run(self):
        if self.running:
            return
        self.running = True

        if not self.server_reachable():
            self.__log("Server does not seem to be reachable. Stopping...")
            self.running = False

        self.__log("Server is reachable, all is fine and dandy.")
        # TODO:

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
    parser.add_argument("-p", "--port", help="Destination server port", type=int, default=51276)  # TODO: Arbitrary...
    args = parser.parse_args()

    client = Client(args)
    client.run()
