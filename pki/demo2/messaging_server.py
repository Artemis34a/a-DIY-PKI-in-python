#!/usr/bin/env python3
"""
Serveur de messagerie PKI sécurisé
Gère les communications entre Alice, Bob et Admin
"""

import socket
import threading
import json
import queue
from datetime import datetime
from pathlib import Path
from rich.console import Console

console = Console()


class MessagingServer:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.clients = {}  # {username: socket}
        self.message_queues = {
            'alice': queue.Queue(),
            'bob': queue.Queue(),
            'admin': queue.Queue()
        }
        self.message_history = []
        self.lock = threading.Lock()
        self.running = True

    def start(self):
        """Démarre le serveur"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)

        console.print(f"[green]🚀 Serveur démarré sur {self.host}:{self.port}[/green]")

        try:
            while self.running:
                try:
                    server.settimeout(1.0)
                    client_socket, addr = server.accept()
                    console.print(f"[cyan]📡 Nouvelle connexion depuis {addr}[/cyan]")

                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket,),
                        daemon=True
                    )
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        console.print(f"[red]Erreur acceptation: {e}[/red]")
        finally:
            server.close()
            console.print("[yellow]Serveur arrêté[/yellow]")

    def handle_client(self, client_socket):
        """Gère un client connecté"""
        username = None
        try:
            # Recevoir l'authentification
            auth_data = self.receive_message(client_socket)
            if auth_data and auth_data.get('type') == 'auth':
                username = auth_data['username']

                with self.lock:
                    self.clients[username] = client_socket

                # Confirmer la connexion
                self.send_message(client_socket, {
                    'type': 'auth_success',
                    'message': f'Bienvenue {username}!'
                })

                console.print(f"[green]✓ {username} connecté[/green]")

                # Boucle de réception des messages
                while self.running:
                    data = self.receive_message(client_socket)
                    if not data:
                        break

                    self.process_message(username, data)

        except Exception as e:
            console.print(f"[red]Erreur client {username}: {e}[/red]")
        finally:
            if username:
                with self.lock:
                    if username in self.clients:
                        del self.clients[username]
                console.print(f"[yellow]{username} déconnecté[/yellow]")
            client_socket.close()

    def process_message(self, sender, data):
        """Traite un message reçu"""
        msg_type = data.get('type')

        if msg_type == 'send_message':
            # Message d'un utilisateur à un autre
            recipient = data['recipient']

            # Enregistrer dans l'historique
            with self.lock:
                self.message_history.append({
                    'sender': sender,
                    'recipient': recipient,
                    'timestamp': datetime.now().isoformat(),
                    'encrypted_message': data['encrypted_message'],
                    'signature': data['signature'],
                    'cert_serial': data['cert_serial']
                })

            # Transmettre au destinataire
            with self.lock:
                if recipient in self.clients:
                    self.send_message(self.clients[recipient], {
                        'type': 'incoming_message',
                        'sender': sender,
                        'encrypted_message': data['encrypted_message'],
                        'signature': data['signature'],
                        'cert_serial': data['cert_serial'],
                        'sender_cert': data.get('sender_cert')
                    })

            # Notifier l'admin
            with self.lock:
                if 'admin' in self.clients:
                    self.send_message(self.clients['admin'], {
                        'type': 'message_event',
                        'sender': sender,
                        'recipient': recipient,
                        'timestamp': datetime.now().isoformat()
                    })

        elif msg_type == 'revoke_cert':
            # Révocation par l'admin
            username_to_revoke = data['username']
            reason = data['reason']

            # Diffuser la révocation à tous
            with self.lock:
                for user, sock in self.clients.items():
                    if user != 'admin':
                        self.send_message(sock, {
                            'type': 'cert_revoked',
                            'username': username_to_revoke,
                            'reason': reason
                        })

        elif msg_type == 'get_history':
            # L'admin demande l'historique
            with self.lock:
                if sender == 'admin' and sender in self.clients:
                    self.send_message(self.clients[sender], {
                        'type': 'history',
                        'messages': self.message_history[-20:]  # 20 derniers
                    })

    def send_message(self, sock, data):
        """Envoie un message JSON au client"""
        try:
            message = json.dumps(data).encode('utf-8')
            length = len(message).to_bytes(4, 'big')
            sock.sendall(length + message)
        except Exception as e:
            console.print(f"[red]Erreur envoi: {e}[/red]")

    def receive_message(self, sock):
        """Reçoit un message JSON du client"""
        try:
            # Lire la longueur (4 bytes)
            length_bytes = sock.recv(4)
            if not length_bytes:
                return None

            length = int.from_bytes(length_bytes, 'big')

            # Lire le message
            data = b''
            while len(data) < length:
                chunk = sock.recv(min(length - len(data), 4096))
                if not chunk:
                    return None
                data += chunk

            return json.loads(data.decode('utf-8'))
        except Exception as e:
            return None

    def stop(self):
        """Arrête le serveur"""
        self.running = False


if __name__ == "__main__":
    server = MessagingServer()
    try:
        server.start()
    except KeyboardInterrupt:
        console.print("\n[yellow]Arrêt du serveur...[/yellow]")
        server.stop()