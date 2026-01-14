#!/usr/bin/env python3
"""
Admin Console
Supervises communications and can revoke certificates
"""

import socket
import json
import threading
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from pki import revoke_certificate, display_registry, load_cert

console = Console()


class AdminConsole:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.username = 'admin'
        self.socket = None
        self.running = True
        self.message_events = []

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

    def _send_message(self, data):
        """Send JSON message"""
        try:
            message = json.dumps(data).encode('utf-8')
            self.socket.sendall(len(message).to_bytes(4, 'big') + message)
        except Exception as e:
            console.print(f"[red]Send error: {e}[/red]")

    def _receive_message(self):
        """Receive JSON message"""
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

    def listen_for_events(self):
        """Listen for events"""
        while self.running:
            try:
                data = self._receive_message()
                if not data:
                    break

                if data.get('type') == 'message_event':
                    event = {
                        'sender': data['sender'],
                        'recipient': data['recipient'],
                        'timestamp': data['timestamp']
                    }
                    self.message_events.append(event)

                    timestamp = datetime.fromisoformat(data['timestamp']).strftime("%H:%M:%S")
                    console.print(
                        f"[dim][{timestamp}][/dim] "
                        f"[cyan]{data['sender']}[/cyan] → "
                        f"[magenta]{data['recipient']}[/magenta]"
                    )

            except Exception as e:
                if self.running:
                    console.print(f"[red]Listen error: {e}[/red]")
                break

    def revoke_user_certificate(self):
        """Revoke user certificate"""
        console.print("\n" + "=" * 60)
        console.print(Panel.fit(
            "[bold red]🚫 CERTIFICATE REVOCATION[/bold red]",
            border_style="red"
        ))

        user = Prompt.ask(
            "Which user to revoke?",
            choices=["alice", "bob", "cancel"],
            default="cancel"
        )

        if user == "cancel":
            console.print("[yellow]Cancelled[/yellow]")
            return

        if not Confirm.ask(f"[red]Are you sure you want to revoke {user}'s certificate?[/red]"):
            console.print("[yellow]Cancelled[/yellow]")
            return

        reasons = {
            "1": "key_compromise",
            "2": "affiliation_changed",
            "3": "superseded",
            "4": "cessation_of_operation",
            "5": "privilege_withdrawn"
        }

        console.print("\n[cyan]Revocation reasons:[/cyan]")
        for k, v in reasons.items():
            console.print(f"  {k}. {v}")

        reason_choice = Prompt.ask("Reason", choices=list(reasons.keys()), default="1")
        reason = reasons[reason_choice]

        try:
            cert = load_cert(user)
            serial = f"{cert.serial_number:X}"

            if revoke_certificate(serial, reason):
                self._send_message({
                    'type': 'revoke_cert',
                    'username': user,
                    'reason': reason
                })

                console.print(f"\n[green]✓ {user}'s certificate revoked successfully[/green]")
                console.print(f"[green]All clients have been notified[/green]")
            else:
                console.print(f"\n[red]✗ Revocation failed[/red]")

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    def show_statistics(self):
        """Display statistics"""
        console.print("\n" + "=" * 60)
        console.print(Panel.fit(
            "[bold yellow]📊 STATISTICS[/bold yellow]",
            border_style="yellow"
        ))

        alice_sent = sum(1 for e in self.message_events if e['sender'] == 'alice')
        bob_sent = sum(1 for e in self.message_events if e['sender'] == 'bob')
        total = len(self.message_events)

        table = Table(title="Messages exchanged", border_style="yellow")
        table.add_column("User", style="cyan")
        table.add_column("Messages sent", style="magenta")

        table.add_row("Alice", str(alice_sent))
        table.add_row("Bob", str(bob_sent))
        table.add_row("[bold]Total[/bold]", f"[bold]{total}[/bold]")

        console.print(table)
        console.print()

    def interactive_loop(self):
        """Main interactive loop"""
        console.print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🔐 ADMIN CONSOLE - PKI Supervision                     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
        """, style="bold green")

        console.print("[cyan]Commands: revoke | stats | registry | help | quit[/cyan]")
        console.print("\n[bold green]📡 LIVE FEED[/bold green]")
        console.print("[dim]Messages will appear here...[/dim]\n")

        while self.running:
            try:
                cmd = Prompt.ask("[bold green]Admin[/bold green]").lower().strip()

                if not cmd:
                    continue

                if cmd in ['quit', 'exit', 'q']:
                    console.print("[yellow]Disconnecting...[/yellow]")
                    break
                elif cmd == 'revoke':
                    self.revoke_user_certificate()
                elif cmd == 'stats':
                    self.show_statistics()
                elif cmd == 'registry':
                    console.print("\n" + "=" * 60)
                    display_registry()
                    console.print()
                elif cmd in ['help', '?']:
                    console.print("\n[cyan]Commands:[/cyan]")
                    console.print("  revoke   - Revoke a certificate")
                    console.print("  stats    - Show statistics")
                    console.print("  registry - Show PKI registry")
                    console.print("  help     - Show this help")
                    console.print("  quit     - Exit\n")
                else:
                    console.print(f"[red]Unknown command: {cmd}[/red]")

            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted...[/yellow]")
                break
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

        self.running = False

    def start(self):
        """Start admin console"""
        if not self.connect():
            return

        threading.Thread(target=self.listen_for_events, daemon=True).start()

        try:
            self.interactive_loop()
        finally:
            self.running = False
            if self.socket:
                self.socket.close()
            console.print("[green]✓ Disconnected[/green]")


if __name__ == "__main__":
    AdminConsole().start()