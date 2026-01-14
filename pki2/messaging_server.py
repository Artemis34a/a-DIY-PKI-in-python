#!/usr/bin/env python3
"""
Secure PKI Messaging Server
Manages communications between clients and admin
"""

import socket
import threading
import json
from datetime import datetime
from rich.console import Console

console = Console()


class MessagingServer:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.clients = {}
        self.message_history = []
        self.lock = threading.Lock()
        self.running = True

    def start(self):
        """Start the server"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(5)
            console.print(f"[green]🚀 Server started on {self.host}:{self.port}[/green]")

            try:
                while self.running:
                    server.settimeout(1.0)
                    try:
                        client_socket, addr = server.accept()
                        console.print(f"[cyan]📡 Connection from {addr}[/cyan]")
                        threading.Thread(
                            target=self.handle_client,
                            args=(client_socket,),
                            daemon=True
                        ).start()
                    except socket.timeout:
                        continue
            except KeyboardInterrupt:
                console.print("\n[yellow]Shutting down...[/yellow]")
            finally:
                self.running = False

    def handle_client(self, client_socket):
        """Handle connected client"""
        username = None
        try:
            auth_data = self._receive_message(client_socket)
            if auth_data and auth_data.get('type') == 'auth':
                username = auth_data['username']
                with self.lock:
                    self.clients[username] = client_socket

                self._send_message(client_socket, {
                    'type': 'auth_success',
                    'message': f'Welcome {username}!'
                })
                console.print(f"[green]✓ {username} connected[/green]")

                while self.running:
                    data = self._receive_message(client_socket)
                    if not data:
                        break
                    self._process_message(username, data)

        except Exception as e:
            console.print(f"[red]Client error {username}: {e}[/red]")
        finally:
            if username:
                with self.lock:
                    self.clients.pop(username, None)
                console.print(f"[yellow]{username} disconnected[/yellow]")
            client_socket.close()

    def _process_message(self, sender, data):
        """Process received message"""
        msg_type = data.get('type')

        if msg_type == 'send_message':
            recipient = data['recipient']

            with self.lock:
                self.message_history.append({
                    'sender': sender,
                    'recipient': recipient,
                    'timestamp': datetime.now().isoformat(),
                    'encrypted_message': data['encrypted_message'],
                    'signature': data['signature'],
                    'cert_serial': data['cert_serial']
                })

                # Forward to recipient
                if recipient in self.clients:
                    self._send_message(self.clients[recipient], {
                        'type': 'incoming_message',
                        'sender': sender,
                        'encrypted_message': data['encrypted_message'],
                        'signature': data['signature'],
                        'sender_cert_serial': data['cert_serial'],  # Utiliser le bon nom
                        'sender_cert': data.get('sender_cert')
                    })

                # Notify admin
                if 'admin' in self.clients:
                    self._send_message(self.clients['admin'], {
                        'type': 'message_event',
                        'sender': sender,
                        'recipient': recipient,
                        'timestamp': datetime.now().isoformat()
                    })

        elif msg_type == 'revoke_cert':
            username_to_revoke = data['username']
            reason = data['reason']

            with self.lock:
                for user, sock in self.clients.items():
                    if user != 'admin':
                        self._send_message(sock, {
                            'type': 'cert_revoked',
                            'username': username_to_revoke,
                            'reason': reason
                        })

    def _send_message(self, sock, data):
        """Send JSON message to client"""
        try:
            message = json.dumps(data).encode('utf-8')
            sock.sendall(len(message).to_bytes(4, 'big') + message)
        except Exception as e:
            console.print(f"[red]Send error: {e}[/red]")

    def _receive_message(self, sock):
        """Receive JSON message from client"""
        try:
            length_bytes = sock.recv(4)
            if not length_bytes:
                return None

            length = int.from_bytes(length_bytes, 'big')
            data = b''
            while len(data) < length:
                chunk = sock.recv(min(length - len(data), 4096))
                if not chunk:
                    return None
                data += chunk

            return json.loads(data.decode('utf-8'))
        except:
            return None


if __name__ == "__main__":
    MessagingServer().start()