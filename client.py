import socket
import sys
import json
import time
from threading import Thread, Event
import os
import threading
import logging
import select

stopEvent = Event()

class CommandExecutor(Thread):
    def __init__(self, udp_client: socket.socket, server_address: tuple[str, int]):
        super().__init__()
        self.udp_client = udp_client
        self.server_address = server_address

    def handle_lap(self):
        self.udp_client.sendto(json.dumps({"command": "LAP"}).encode('utf-8'), self.server_address)
        response, server = self.udp_client.recvfrom(2048)
        response_data: dict = json.loads(response)
        length = len(response_data["response"])
        if length <= 0:
            print("No active peers")
        else:
            print(f"{length} active peers:")
            for i in response_data["response"]:
                print(i)

    def handle_lpf(self):
        self.udp_client.sendto(json.dumps({"command": "LPF"}).encode('utf-8'), self.server_address)
        response, server = self.udp_client.recvfrom(2048)
        response_data: dict = json.loads(response)
        length = len(response_data["response"])
        if length <= 0:
            print("No files published")
        else:
            print(f"{length} files published:")
            for i in response_data["response"]:
                print(i)

    def handle_pub(self, extra):
        self.udp_client.sendto(json.dumps({"command": "PUB", "content": extra}).encode('utf-8'), self.server_address)
        response, server = self.udp_client.recvfrom(2048)
        response_data: dict = json.loads(response)
        if response_data["response"] == "OK":
            print("File published successfully")
        else:
            print("File publication failed")

    def handle_unp(self, extra):
        self.udp_client.sendto(json.dumps({"command": "UNP", "content": extra}).encode('utf-8'), self.server_address)
        response, server = self.udp_client.recvfrom(2048)
        response_data: dict = json.loads(response)
        if response_data["response"] == "OK":
            print("File unpublished successfully")
        else:
            print("File unpublication failed")

    def handle_sch(self, extra):
        self.udp_client.sendto(json.dumps({"command": "SCH", "content": extra}).encode('utf-8'), self.server_address)
        response, server = self.udp_client.recvfrom(2048)
        response_data: dict = json.loads(response)
        length = len(response_data["response"])
        if length <= 0:
            print("No files found")
        else:
            print(f"{length} files found:")
            for i in response_data["response"]:
                print(i)

    def handle_get(self, extra):
        self.udp_client.sendto(json.dumps({"command": "GET", "content": extra}).encode('utf-8'), self.server_address)
        response, server = self.udp_client.recvfrom(2048)
        response_data: dict = json.loads(response)
        peer_port = response_data["response"]

        if not peer_port or peer_port == "ERR":
            print("File not found")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_client:
                tcp_client.connect(("127.0.0.1", peer_port))
                tcp_client.sendall(json.dumps({"command": "GET", "filename": extra}).encode('utf-8'))

                cwd = os.getcwd()
                with open(os.path.join(cwd, extra), "wb") as file:
                    while True:
                        data = tcp_client.recv(2048)
                        if not data:
                            break
                        file.write(data)
                print(f"{extra} downloaded successfully")
        except Exception as e:
            print(f"Error: {e} during file transfer.")

    def run(self):
        while not stopEvent.is_set():
            user_input = input("> ")
            processed_input = user_input.split(" ")
            if len(processed_input) > 2 or len(processed_input) <= 0:
                print("Unknown command: Available commands are: get, lap, lpf, pub, sch, unp, xit")
                continue

            command, *extra = processed_input
            extra = extra[0] if extra else None
            #commands
            command_handlers = {
                "lap": self.handle_lap,
                "lpf": self.handle_lpf,
                "pub": lambda: self.handle_pub(extra),
                "unp": lambda: self.handle_unp(extra),
                "sch": lambda: self.handle_sch(extra),
                "get": lambda: self.handle_get(extra),
            }

            if command in command_handlers:
                try:
                    command_handlers[command]()
                except Exception as e:
                    print(f"Error handling command {command}: {e}")
            elif command == "xit":
                print("Goodbye!")
                stopEvent.set()
                break
            else:
                print("Unknown command: Available commands are: get, lap, lpf, pub, sch, unp, xit")



#HeartBeat  of the program
class HeartbeatSender(threading.Thread):

    def __init__(self, client_socket: socket.socket, server_address: tuple[str, int], interval: int = 2):
        super().__init__()
        self.client_socket = client_socket
        self.server_address = server_address
        self.interval = interval
        self.stop_event = threading.Event()
        self.message = json.dumps({"command": "HBT"}).encode('utf-8')
        self.logger = logging.getLogger(__name__)

    def send_heartbeat(self):
        try:
            self.client_socket.sendto(self.message, self.server_address)
            self.logger.info(f"Heartbeat sent to {self.server_address}")
        except Exception as e:
            self.logger.error(f"Failed to send heartbeat: {e}")

    def run(self):
        self.logger.info("HeartbeatSender started.")
        while not self.stop_event.is_set():
            self.send_heartbeat()
            time.sleep(self.interval)
        self.logger.info("HeartbeatSender stopped.")
        self.client_socket.close()

    def stop(self):
        self.logger.info("Stopping HeartbeatSender...")
        self.stop_event.set()

class RequestHandler(Thread):
    def __init__(self, connection: socket.socket, address: tuple[str, int]):
        super().__init__()
        self.connection = connection
        self.address = address

    def run(self):
        try:
            request_data = self.connection.recv(2048).decode('utf-8')
            request = json.loads(request_data)

            if request.get("command") == "GET" and (filename := request.get("filename")):
                self.send_file(filename)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error processing request from {self.address}: {e}")
            self.connection.sendall(b"ERROR")
        except Exception as e:
            print(f"Unexpected error: {e}")
        finally:
            self.connection.close()

    def send_file(self, filename: str):
        try:
            filepath = os.path.join(os.getcwd(), filename)
            with open(filepath, "rb") as file:
                while chunk := file.read(2048):
                    self.connection.sendall(chunk)
        except FileNotFoundError:
            print(f"File not found: {filename}")
            self.connection.sendall(b"FILE_NOT_FOUND")
        except Exception as e:
            print(f"Error sending file {filename}: {e}")

#listens to requests
class RequestListener(Thread):

    def __init__(self, tcp_socket: socket.socket):
        super().__init__()
        self.socket = tcp_socket
        self.socket.settimeout(1)

    def run(self):
        while not stopEvent.is_set():
            try:
                connection, address = self.socket.accept()
                handler = RequestHandler(connection, address)
                handler.start()
            except TimeoutError:
                continue
            except Exception as e:
                print(f"Error accepting connection: {e}")
        self.socket.close()

def authenticate_user(udpClientSocket, serverAddress, tcpPort):
    """Handles user authentication."""
    def is_valid_credential(text):
        return text.isprintable() and len(text) <= 16
    #validates username and password
    while True:
        username = input('Enter username: ')
        password = input('Enter password: ')

        if not is_valid_credential(username) or not is_valid_credential(password):
            print("Authentication failed. Please try again.")
            continue

        data = {
            "command": "AUTH",
            "username": username,
            "password": password,
            "tcpPort": tcpPort
        }
        json_data = json.dumps(data).encode('utf-8')
        udpClientSocket.settimeout(5)
        #try socket
        try:
            udpClientSocket.sendto(json_data, serverAddress)
            response, _ = udpClientSocket.recvfrom(2048)

            if not response:
                print("No response received from server.")
                continue

            response_data = json.loads(response)
            if response_data.get("response") == "OK":
                break
            else:
                print("Authentication failed. Please try again.")
        except socket.timeout:
            print("Server could not be reached. Please try again.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    print("Welcome to BitTrickle!")
    print("Available commands are: get, lap, lpf, pub, sch, unp, xit")

def main():
    if len(sys.argv) != 2:
        print("\n===== Error usage, python3 client.py SERVER_PORT ======\n")
        exit(0)

    serverPort = int(sys.argv[1])
    serverHost = "127.0.0.1"
    serverAddress = (serverHost, serverPort)

    # Using context managers for both UDP and TCP sockets
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udpClientSocket, \
         socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcpServerSocket:

        tcpServerSocket.bind(('127.0.0.1', 0))
        tcpServerSocket.listen(5)
        tcpPort = tcpServerSocket.getsockname()[1]
        authenticate_user(udpClientSocket, serverAddress, tcpPort)

        # Start components
        heartbeat = HeartbeatSender(udpClientSocket, serverAddress)
        command = CommandExecutor(udpClientSocket, serverAddress)
        listener = RequestListener(tcpServerSocket)

        heartbeat.start()
        listener.start()
        command.start()

        try:
            listener.join()
            heartbeat.join()
            command.join()
        except KeyboardInterrupt:
            stopEvent.set()
            heartbeat.stop()
        finally:
        # Stop all threads and close
            stopEvent.set()
            heartbeat.stop()
            tcpServerSocket.close()
            udpClientSocket.close()
if __name__ == "__main__":
    main()