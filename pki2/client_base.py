#!/usr/bin/env python3
"""
Base client class for Alice and Bob
Handles authentication, encryption, and messaging
"""

import socket
import json
import threading
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

sys.path.insert(0, str(Path(__file__).parent))
from pki import load_cert, load_key, check_revocation
from pki_encryption import sign_and_encrypt_message, decrypt_and_verify_message

console = Console()


class SecureClient:
    def __init__(self, username, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.username = username
        self.other_user = 'bob' if username == 'alice' else 'alice'
        self.socket = None
        self.running = True
        self.cert = None
        self.private_key = None
        self.other_cert = None
        self.cert_revoked = False

    def connect(self):
        """Connect to server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))

            self._send_message({'type': 'auth', 'username': self.username})
            response = self._receive_message()

            if response and response.get('type') == 'auth_success':
                console.print(f"[green]✓ {response['message']}[/green]")
                return True
            return False
        except Exception as e:
            console.print(f"[red]Connection error: {e}[/red]")
            return False

    def load_credentials(self):
        """Load certificate and private key"""
        try:
            console.print("[cyan]📋 Loading credentials...[/cyan]")
            self.cert = load_cert(self.username)
            self.private_key = load_key(self.username, password=None)
            self.other_cert = load_cert(self.other_user)
            console.print("[green]✓ Credentials loaded[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Error loading credentials: {e}[/red]")
            console.print("[yellow]Run setup.py first[/yellow]")
            return False

    def _send_message(self, data):
        """Send JSON message to server"""
        try:
            message = json.dumps(data).encode('utf-8')
            self.socket.sendall(len(message).to_bytes(4, 'big') + message)
        except Exception as e:
            console.print(f"[red]Send error: {e}[/red]")

    def _receive_message(self):
        """Receive JSON message from server"""
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
        except:
            return None

    def listen_for_messages(self):
        """Listen for incoming messages"""
        while self.running:
            try:
                data = self._receive_message()
                if not data:
                    break

                msg_type = data.get('type')

                if msg_type == 'incoming_message':
                    self._handle_incoming_message(data)
                elif msg_type == 'cert_revoked':
                    self._handle_revocation(data)

            except Exception as e:
                if self.running:
                    console.print(f"[red]Listen error: {e}[/red]")
                break

    def _handle_incoming_message(self, data):
        """Handle incoming encrypted message"""
        console.print("\n" + "=" * 60)
        console.print(Panel.fit(
            f"[bold cyan]📨 NEW MESSAGE[/bold cyan]",
            border_style="cyan"
        ))
        console.print(f"[yellow]From:[/yellow] [cyan]{data['sender']}[/cyan]")

        try:
            success, result, _ = decrypt_and_verify_message(
                data, self.private_key, check_revocation
            )

            if success:
                console.print(f"[green]✓ Valid signature[/green]")
                console.print(f"\n[bold white]Message:[/bold white] [green]{result.decode('utf-8')}[/green]")
            else:
                console.print(f"[red]✗ {result}[/red]")
                console.print("[red]This message is not trustworthy![/red]")

        except Exception as e:
            console.print(f"[red]Decryption error: {e}[/red]")

        console.print("=" * 60 + "\n")

    def _handle_revocation(self, data):
        """Handle certificate revocation"""
        if data['username'] == self.username:
            self.cert_revoked = True
            console.print(f"\n[red bold]⚠️ YOUR CERTIFICATE HAS BEEN REVOKED![/red bold]")
            console.print(f"[red]Reason: {data['reason']}[/red]")
            console.print("[red]You can no longer send secure messages.[/red]\n")
        else:
            console.print(f"\n[yellow]⚠️ {data['username']}'s certificate revoked ({data['reason']})[/yellow]\n")

    def send_encrypted_message(self, message_text):
        """Send encrypted and signed message"""
        if self.cert_revoked:
            console.print("[red]✗ Cannot send: your certificate is revoked[/red]")
            return

        try:
            # Check if recipient is revoked
            other_serial = f"{self.other_cert.serial_number:X}"
            revocation_status = check_revocation(other_serial)

            if revocation_status['status'] == 'revoked':
                console.print(f"[red]⚠️ WARNING: {self.other_user}'s certificate is revoked![/red]")
                console.print(f"[red]Reason: {revocation_status['reason']}[/red]")
                console.print(f"[red]{self.other_user} is not trustworthy. Message not sent.[/red]")
                return

            # Encrypt and sign
            encrypted_data = sign_and_encrypt_message(
                message_text.encode('utf-8'),
                self.private_key,
                self.cert,
                self.other_cert
            )

            # Send via server
            self._send_message({
                'type': 'send_message',
                'recipient': self.other_user,
                'encrypted_message': encrypted_data['encrypted_message'],
                'signature': encrypted_data['signature'],
                'cert_serial': encrypted_data['sender_cert_serial'],
                'sender_cert': encrypted_data['sender_cert']
            })

            console.print("[green]✓ Message sent and encrypted[/green]")

        except Exception as e:
            console.print(f"[red]Send error: {e}[/red]")

    def interactive_loop(self):
        """Main interactive loop"""
        color = "cyan" if self.username == 'alice' else "magenta"
        console.print(f"""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   👤 {self.username.upper()} - Secure PKI Messaging                ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
        """, style=f"bold {color}")

        console.print(f"[{color}]Commands:[/{color}]")
        console.print("  • Type message → send to " + self.other_user)
        console.print("  • 'status' → view certificate status")
        console.print("  • 'quit' → exit\n")

        while self.running:
            try:
                user_input = Prompt.ask(f"[bold {color}]{self.username.capitalize()}[/bold {color}]")

                if not user_input:
                    continue

                command = user_input.lower().strip()

                if command in ['quit', 'exit']:
                    console.print("[yellow]Disconnecting...[/yellow]")
                    break
                elif command == 'status':
                    status = "REVOKED" if self.cert_revoked else "ACTIVE"
                    color_status = "red" if self.cert_revoked else "green"
                    console.print(f"[{color_status}]Certificate status: {status}[/{color_status}]")
                else:
                    self.send_encrypted_message(user_input)

            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted...[/yellow]")
                break
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

        self.running = False

    def start(self):
        """Start the client"""
        if not self.load_credentials():
            return

        if not self.connect():
            return

        threading.Thread(target=self.listen_for_messages, daemon=True).start()

        try:
            self.interactive_loop()
        finally:
            self.running = False
            if self.socket:
                self.socket.close()
            console.print("[green]✓ Disconnected[/green]")


if __name__ == "__main__":
    import sys

    username = sys.argv[1] if len(sys.argv) > 1 else 'alice'
    SecureClient(username).start()