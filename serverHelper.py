import os
from datetime import datetime, timedelta
from pathlib  import Path

class PeerServer:
    def __init__(self, credentials_file='credentials.txt'):
        self.user_credentials = {}
        self.last_heartbeat = {}
        self.ip_to_user = {}
        self.shared_files = {}
        self.user_tcp_ports = {}

        self.load_credentials(credentials_file)

    def load_credentials(self, credentials_file):
        credentials_path = Path(os.getcwd()) / credentials_file

        if not credentials_path.is_file():
            raise FileNotFoundError(f"Credentials file '{credentials_file}' not found in the current directory.")

        try:
            with credentials_path.open('r') as file:
                for line in file:
                    self._process_credential_line(line.strip())
        except IOError as e:
            raise IOError(f"Error reading the credentials file: {e}")

    def _process_credential_line(self, line):
        credentials = line.split()
        if len(credentials) != 2:
            raise ValueError("Authentication failed. Please try again.")

        username, password = credentials
        if not self.is_valid_input(username) or not self.is_valid_input(password):
            raise ValueError("Authentication failed. Please try again.")

        self.user_credentials[username] = password
        self.last_heartbeat[username] = None

    def is_valid_input(self, input_str):
        return input_str.isalnum() and len(input_str) > 0

    def authenticate_user(self, username: str, password: str, ip_address, tcp_port):
        if self.user_credentials.get(username) != password:
            return False
        if username in self.last_heartbeat and self.last_heartbeat[username] is not None and (datetime.now() - self.last_heartbeat[username]) <= timedelta(seconds=3):
            return False
        self.ip_to_user[ip_address] = username
        self.user_tcp_ports[username] = tcp_port
        self.last_heartbeat[username] = datetime.now()
        return True

    def find_peer_with_file(self, file_name):
        # Check if the file is shared by any peer
        shared_users = self.shared_files.get(file_name)
        if not shared_users:
            return None

        active_threshold = datetime.now() - timedelta(seconds=3)

        for user in shared_users:
            last_heartbeat = self.last_heartbeat.get(user)
            if last_heartbeat and last_heartbeat >= active_threshold:
                return self.user_tcp_ports.get(user)
        return None

    def is_valid_input(self, text: str):
        return text.isprintable() and len(text) <= 16

    def record_heartbeat(self, ip_address):
        username = self.ip_to_user.get(ip_address)
        if username is None:
            raise ValueError("Invalid IP address")
        self.last_heartbeat[username] = datetime.now()

    def get_user_by_ip(self, ip_address):
        return self.ip_to_user.get(ip_address)

    def share_file(self, file_name, ip_address):
        username = self.get_user_by_ip(ip_address)
        if file_name not in self.shared_files:
            self.shared_files[file_name] = set()

        self.shared_files[file_name].add(username)
        return True

    def unshare_file(self, file_name, ip_address):
        username = self.get_user_by_ip(ip_address)
        if file_name in self.shared_files and username in self.shared_files[file_name]:
            self.shared_files[file_name].remove(username)
            if not self.shared_files[file_name]:
                self.shared_files.pop(file_name)

            return True

        return False

    def search_files_by_keyword(self, keyword, ip_address):
        username = self.get_user_by_ip(ip_address)
        return [
            file_name
            for file_name, users in self.shared_files.items()
            if keyword in file_name and username not in users
        ]

    def get_active_peers_except(self, ip_address):
        username = self.get_user_by_ip(ip_address)
        now = datetime.now()
        active_threshold = now - timedelta(seconds=3)
        active_users = [user for user, timestamp in self.last_heartbeat.items() if timestamp and timestamp > active_threshold]
        if username in active_users:
            active_users.remove(username)
        return active_users

    def get_user_shared_files(self, ip_address):
        username = self.get_user_by_ip(ip_address)
        user_files = []
        for file, users in self.shared_files.items():
            if username in users:
                user_files.append(file)
        return user_files

