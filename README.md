# BitTrickle: A UDP-Based Peer-to-Peer File Sharing System

BitTrickle is a lightweight, UDP-based peer-to-peer file sharing and discovery system. It enables authenticated peers to connect to a central server, publish files, search for files across peers, and download files using direct TCP connections.

## Features

- User Authentication – Authenticates peers using a credential file.
- Peer Discovery – Lists currently active peers using heartbeats.
- File Publishing – Publish/unpublish local files to share with the network.
- File Search – Search for files shared by other peers.
- File Downloading – Download shared files directly from peers via TCP.
- Heartbeat Mechanism– Maintains active peer list via periodic heartbeat signals.

## Components

### 1. `server.py`
- Listens for incoming UDP messages from clients.
- Handles all peer commands (`AUTH`, `HBT`, `LAP`, `LPF`, `PUB`, `UNP`, `SCH`, `GET`).
- Relies on `PeerServer` from `serverHelper.py` for user state and file management.

### 2. `serverHelper.py`
- Contains the `PeerServer` class to manage:
  - User authentication
  - File sharing
  - Heartbeat tracking
  - Active peer/file search logic

### 3. `client.py`
- Authenticates with the server via UDP.
- Starts:
  - `CommandExecutor`: CLI interface for commands.
  - `HeartbeatSender`: Sends heartbeat messages periodically.
  - `RequestListener`: Listens for file download requests via TCP.

### 4. `credentials.txt`
- Contains hardcoded username-password pairs used for authentication.

## Commands

Run from the client command line after authentication:

| Command | Description                          |
|---------|--------------------------------------|
| `lap`   | List active peers                    |
| `lpf`   | List published files by the user     |
| `pub`   | Publish a file                       |
| `unp`   | Unpublish a file                     |
| `sch`   | Search for a file by keyword         |
| `get`   | Download a file from another peer    |
| `xit`   | Exit the client                      |

## How to Run

### Start the Server
```bash
python3 server.py <PORT>
Start a Client
bash
Copy
Edit
python3 client.py <SERVER_PORT>
```

## Example
```bash
$ python3 server.py 8888
```
 In another terminal
```
$ python3 client.py 8888
Enter username: yoda
Enter password: wise@!man
> pub testfile.txt
> sch test
> get testfile.txt
```
