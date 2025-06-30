from socket import *
from threading import Thread
import sys, json
from serverHelper import PeerServer
from datetime import datetime

if len(sys.argv) != 2:
    print("\n===== Error usage, python3 UDPServer.py SERVER_PORT ======\n")
    exit(0)
server_host = "127.0.0.1"
server_port = int(sys.argv[1])
server_address = (server_host, server_port)

server_socket = socket(AF_INET, SOCK_DGRAM)
server_socket.bind(server_address)


class ServerThread(Thread):
    def __init__(self, client_address, message, manager: PeerServer):
        Thread.__init__(self)
        self.client_address = client_address
        self.message: dict = json.loads(message)
        self.manager = manager

    def run(self):
        if "command" not in self.message:
            print("Unknown command received")
            return

        command = self.message.get("command")
        print(f"{datetime.now()}: {self.client_address[1]}: Received {command} from {auth.get_user_by_ip(self.client_address)}")

        # Table for commands
        command_dispatch = {
            "AUTH": self._process_auth,
            "HBT": self._process_heartbeat,
            "LAP": self._process_list_active_peers,
            "LPF": self._process_list_peer_files,
            "PUB": self._process_publish_file,
            "UNP": self._process_unpublish_file,
            "SCH": self._process_search_files,
            "GET": self._process_get_file,
        }


        handler = command_dispatch.get(command, self._unknown_command)
        data = handler()

        if data:
            print(f"{datetime.now()}: Sent {data} to {auth.get_user_by_ip(self.client_address)}")
            server_socket.sendto(json.dumps(data).encode('utf-8'), self.client_address)

    def _process_auth(self):
        if self.manager.authenticate_user(
            self.message["username"],
            self.message["password"],
            self.client_address,
            self.message["tcpPort"]
        ):
            return {"response": "OK"}
        return {"response": "ERR"}

    def _process_heartbeat(self):
        self.manager.record_heartbeat(self.client_address)

        return None

    def _process_list_active_peers(self):
        return {"response": self.manager.get_active_peers_except(self.client_address)}

    def _process_list_peer_files(self):
        return {"response": list(self.manager.get_user_shared_files(self.client_address))}

    def _process_publish_file(self):
        self.manager.share_file(self.message["content"], self.client_address)
        return {"response": "OK"}

    def _process_unpublish_file(self):
        if self.manager.unshare_file(self.message["content"], self.client_address):
            return {"response": "OK"}
        return {"response": "ERR"}

    def _process_search_files(self):
        return {"response": self.manager.search_files_by_keyword(self.message["content"], self.client_address)}

    def _process_get_file(self):
        filename = self.message["content"]
        result = self.manager.find_peer_with_file(filename)
        if result is None:
            return {"response": "ERR"}
        return {"response": result}

    def _unknown_command(self):
        print("Unknown command received")
        return None

print("\n===== UDP Server is running =====")
print("===== Waiting for client requests... =====")

auth = PeerServer()
while True:
    data, client_address = server_socket.recvfrom(2048)
    client_thread = ServerThread(client_address, data, auth)
    client_thread.start()
    client_thread.join()