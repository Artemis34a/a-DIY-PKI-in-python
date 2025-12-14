#!/usr/bin/env python3
"""
Console interactive pour Alice
Permet d'envoyer et recevoir des messages chiffrés
"""

import socket
import json
import threading
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
import base64

# Import des modules PKI
sys.path.insert(0, str(Path(__file__).parent))
from pki import load_cert, load_key, check_revocation
from pki_encryption import (
    sign_and_encrypt_message,
    decrypt_and_verify_message,
    import_cert_from_string
)

console = Console()


class AliceClient:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.username = 'alice'
        self.socket = None
        self.running = True
        self.cert = None
        self.private_key = None
        self.bob_cert = None
        self.cert_revoked = False

    def connect(self):
        """Connexion au serveur"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))

            # S'authentifier
            self.send_message({
                'type': 'auth',
                'username': self.username
            })

            # Attendre confirmation
            response = self.receive_message()
            if response and response.get('type') == 'auth_success':
                console.print(f"[green]✓ {response['message']}[/green]")
                return True
            return False

        except Exception as e:
            console.print(f"[red]Erreur de connexion: {e}[/red]")
            return False

    def load_credentials(self):
        """Charge le certificat et la clé privée"""
        try:
            console.print("[cyan]📋 Chargement des identifiants...[/cyan]")
            self.cert = load_cert('alice')
            self.private_key = load_key('alice', password=None)
            console.print("[green]✓ Identifiants chargés[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Erreur chargement identifiants: {e}[/red]")
            console.print("[yellow]Assurez-vous d'avoir exécuté setup.py d'abord[/yellow]")
            return False

    def load_bob_cert(self):
        """Charge le certificat de Bob"""
        try:
            self.bob_cert = load_cert('bob')
            console.print("[green]✓ Certificat de Bob chargé[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Erreur chargement certificat Bob: {e}[/red]")
            return False

    def send_message(self, data):
        """Envoie un message JSON au serveur"""
        try:
            message = json.dumps(data).encode('utf-8')
            length = len(message).to_bytes(4, 'big')
            self.socket.sendall(length + message)
        except Exception as e:
            console.print(f"[red]Erreur envoi: {e}[/red]")

    def receive_message(self):
        """Reçoit un message JSON du serveur"""
        try:
            length_bytes = self.socket.recv(4)
            if not length_bytes:
                return None

            length = int.from_bytes(length_bytes, 'big')
            data = b''
            while len(data) < length:
                chunk = self.socket.recv(min(length - len(data), 4096))
                if not chunk:
                    return None
                data += chunk

            return json.loads(data.decode('utf-8'))
        except Exception as e:
            return None

    def listen_for_messages(self):
        """Thread d'écoute des messages entrants"""
        while self.running:
            try:
                data = self.receive_message()
                if not data:
                    break

                msg_type = data.get('type')

                if msg_type == 'incoming_message':
                    self.handle_incoming_message(data)

                elif msg_type == 'cert_revoked':
                    if data['username'] == 'alice':
                        self.cert_revoked = True
                        console.print(f"\n[red bold]⚠️ VOTRE CERTIFICAT A ÉTÉ RÉVOQUÉ![/red bold]")
                        console.print(f"[red]Raison: {data['reason']}[/red]")
                        console.print("[red]Vous ne pouvez plus envoyer de messages sécurisés.[/red]\n")
                    elif data['username'] == 'bob':
                        console.print(f"\n[yellow]⚠️ Le certificat de Bob a été révoqué ({data['reason']})[/yellow]\n")

            except Exception as e:
                if self.running:
                    console.print(f"[red]Erreur écoute: {e}[/red]")
                break

    def handle_incoming_message(self, data):
        """Traite un message entrant"""
        console.print("\n" + "=" * 60)
        console.print(Panel.fit(
            "[bold cyan]📨 NOUVEAU MESSAGE[/bold cyan]",
            border_style="cyan"
        ))

        sender = data['sender']
        console.print(f"[yellow]De:[/yellow] [cyan]{sender}[/cyan]")

        # Déchiffrer et vérifier
        try:
            success, result, sender_serial = decrypt_and_verify_message(
                data,
                self.private_key,
                check_revocation
            )

            if success:
                message_text = result.decode('utf-8')
                console.print(f"[green]✓ Signature valide[/green]")
                console.print(f"\n[bold white]Message:[/bold white] [green]{message_text}[/green]")
            else:
                console.print(f"[red]✗ {result}[/red]")
                console.print("[red]Ce message n'est pas fiable![/red]")

        except Exception as e:
            console.print(f"[red]Erreur déchiffrement: {e}[/red]")

        console.print("=" * 60 + "\n")

    def send_encrypted_message(self, recipient, message_text):
        """Envoie un message chiffré et signé"""
        if self.cert_revoked:
            console.print("[red]✗ Impossible d'envoyer: votre certificat est révoqué[/red]")
            return

        if recipient != 'bob':
            console.print("[red]Vous ne pouvez envoyer qu'à Bob[/red]")
            return

        if not self.bob_cert:
            console.print("[red]Certificat de Bob non disponible[/red]")
            return

        try:
            # Vérifier si Bob est révoqué
            bob_serial = f"{self.bob_cert.serial_number:X}"
            revocation_status = check_revocation(bob_serial)

            if revocation_status['status'] == 'revoked':
                console.print(f"[red]⚠️ ATTENTION: Le certificat de Bob est révoqué![/red]")
                console.print(f"[red]Raison: {revocation_status['reason']}[/red]")
                console.print(f"[red]Bob n'est pas fiable. Message non envoyé.[/red]")
                return

            # Chiffrer et signer
            encrypted_data = sign_and_encrypt_message(
                message_text.encode('utf-8'),
                self.private_key,
                self.cert,
                self.bob_cert
            )

            # Envoyer via le serveur
            self.send_message({
                'type': 'send_message',
                'recipient': recipient,
                'encrypted_message': encrypted_data['encrypted_message'],
                'signature': encrypted_data['signature'],
                'cert_serial': encrypted_data['sender_cert_serial'],
                'sender_cert': encrypted_data['sender_cert']
            })

            console.print("[green]✓ Message envoyé et chiffré[/green]")

        except Exception as e:
            console.print(f"[red]Erreur envoi: {e}[/red]")

    def interactive_loop(self):
        """Boucle interactive principale"""
        console.print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   👤 CONSOLE ALICE - Messagerie Sécurisée PKI            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
        """, style="bold cyan")

        console.print("[cyan]Commandes disponibles:[/cyan]")
        console.print("  • Tapez votre message et appuyez sur Entrée pour l'envoyer à Bob")
        console.print("  • 'quit' ou 'exit' pour quitter")
        console.print("  • 'status' pour voir votre statut\n")

        while self.running:
            try:
                user_input = Prompt.ask("[bold cyan]Alice[/bold cyan]")

                if not user_input:
                    continue

                command = user_input.lower().strip()

                if command in ['quit', 'exit']:
                    console.print("[yellow]Déconnexion...[/yellow]")
                    self.running = False
                    break

                elif command == 'status':
                    status = "RÉVOQUÉ" if self.cert_revoked else "ACTIF"
                    color = "red" if self.cert_revoked else "green"
                    console.print(f"[{color}]Statut du certificat: {status}[/{color}]")

                else:
                    # Envoyer le message à Bob
                    self.send_encrypted_message('bob', user_input)

            except KeyboardInterrupt:
                console.print("\n[yellow]Interruption détectée...[/yellow]")
                self.running = False
                break
            except Exception as e:
                console.print(f"[red]Erreur: {e}[/red]")

    def start(self):
        """Démarre le client"""
        # Charger les identifiants
        if not self.load_credentials():
            return

        if not self.load_bob_cert():
            return

        # Connexion au serveur
        if not self.connect():
            return

        # Lancer le thread d'écoute
        listen_thread = threading.Thread(
            target=self.listen_for_messages,
            daemon=True
        )
        listen_thread.start()

        # Boucle interactive
        try:
            self.interactive_loop()
        finally:
            self.running = False
            if self.socket:
                self.socket.close()
            console.print("[green]✓ Déconnecté[/green]")


if __name__ == "__main__":
    client = AliceClient()
    client.start()