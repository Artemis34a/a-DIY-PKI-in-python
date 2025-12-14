#!/usr/bin/env python3
"""
Console d'administration
Supervise les communications et peut révoquer des certificats
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

# Import des modules PKI
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

    def listen_for_events(self):
        """Thread d'écoute des événements"""
        while self.running:
            try:
                data = self.receive_message()
                if not data:
                    break

                msg_type = data.get('type')

                if msg_type == 'message_event':
                    # Enregistrer l'événement
                    event = {
                        'sender': data['sender'],
                        'recipient': data['recipient'],
                        'timestamp': data['timestamp']
                    }
                    self.message_events.append(event)

                    # Afficher en temps réel
                    timestamp = datetime.fromisoformat(data['timestamp']).strftime("%H:%M:%S")
                    console.print(
                        f"[dim][{timestamp}][/dim] "
                        f"[cyan]{data['sender']}[/cyan] → "
                        f"[magenta]{data['recipient']}[/magenta]"
                    )

            except Exception as e:
                if self.running:
                    console.print(f"[red]Erreur écoute: {e}[/red]")
                break

    def show_live_feed(self):
        """Affiche le flux en temps réel"""
        console.print("\n" + "=" * 60)
        console.print(Panel.fit(
            "[bold green]📡 FLUX EN TEMPS RÉEL[/bold green]",
            border_style="green"
        ))
        console.print("[dim]Les messages échangés s'afficheront ici...[/dim]\n")

    def revoke_user_certificate(self):
        """Révoque le certificat d'un utilisateur"""
        console.print("\n" + "=" * 60)
        console.print(Panel.fit(
            "[bold red]🚫 RÉVOCATION DE CERTIFICAT[/bold red]",
            border_style="red"
        ))

        # Choisir l'utilisateur
        user = Prompt.ask(
            "Quel utilisateur voulez-vous révoquer?",
            choices=["alice", "bob", "annuler"],
            default="annuler"
        )

        if user == "annuler":
            console.print("[yellow]Annulé[/yellow]")
            return

        # Confirmer
        if not Confirm.ask(f"[red]Êtes-vous sûr de vouloir révoquer le certificat de {user}?[/red]"):
            console.print("[yellow]Annulé[/yellow]")
            return

        # Choisir la raison
        console.print("\n[cyan]Raisons de révocation:[/cyan]")
        console.print("  1. key_compromise (Clé compromise)")
        console.print("  2. affiliation_changed (Changement d'affiliation)")
        console.print("  3. superseded (Remplacé)")
        console.print("  4. cessation_of_operation (Cessation d'opération)")
        console.print("  5. privilege_withdrawn (Privilège retiré)")

        reason_choice = Prompt.ask(
            "Raison",
            choices=["1", "2", "3", "4", "5"],
            default="1"
        )

        reasons = {
            "1": "key_compromise",
            "2": "affiliation_changed",
            "3": "superseded",
            "4": "cessation_of_operation",
            "5": "privilege_withdrawn"
        }
        reason = reasons[reason_choice]

        try:
            # Charger le certificat pour obtenir le serial
            cert = load_cert(user)
            serial = f"{cert.serial_number:X}"

            # Révoquer localement
            success = revoke_certificate(serial, reason)

            if success:
                # Notifier le serveur
                self.send_message({
                    'type': 'revoke_cert',
                    'username': user,
                    'reason': reason
                })

                console.print(f"\n[green]✓ Certificat de {user} révoqué avec succès[/green]")
                console.print(f"[green]Tous les clients ont été notifiés[/green]")
            else:
                console.print(f"\n[red]✗ Échec de la révocation[/red]")

        except Exception as e:
            console.print(f"[red]Erreur: {e}[/red]")

    def show_statistics(self):
        """Affiche les statistiques"""
        console.print("\n" + "=" * 60)
        console.print(Panel.fit(
            "[bold yellow]📊 STATISTIQUES[/bold yellow]",
            border_style="yellow"
        ))

        # Compter les messages
        alice_sent = sum(1 for e in self.message_events if e['sender'] == 'alice')
        bob_sent = sum(1 for e in self.message_events if e['sender'] == 'bob')
        total = len(self.message_events)

        table = Table(title="Messages échangés", border_style="yellow")
        table.add_column("Utilisateur", style="cyan")
        table.add_column("Messages envoyés", style="magenta")

        table.add_row("Alice", str(alice_sent))
        table.add_row("Bob", str(bob_sent))
        table.add_row("[bold]Total[/bold]", f"[bold]{total}[/bold]")

        console.print(table)
        console.print()

    def show_registry(self):
        """Affiche le registre des certificats"""
        console.print("\n" + "=" * 60)
        display_registry()
        console.print()

    def show_help(self):
        """Affiche l'aide"""
        console.print("\n" + "=" * 60)
        console.print(Panel.fit(
            "[bold cyan]❓ AIDE[/bold cyan]",
            border_style="cyan"
        ))

        console.print("[cyan]Commandes disponibles:[/cyan]")
        console.print("  [bold]revoke[/bold]   - Révoquer un certificat")
        console.print("  [bold]stats[/bold]    - Afficher les statistiques")
        console.print("  [bold]registry[/bold] - Afficher le registre PKI")
        console.print("  [bold]feed[/bold]     - Afficher le flux en temps réel")
        console.print("  [bold]help[/bold]     - Afficher cette aide")
        console.print("  [bold]quit[/bold]     - Quitter\n")

    def interactive_loop(self):
        """Boucle interactive principale"""
        console.print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🔐 CONSOLE ADMIN - Supervision PKI                     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
        """, style="bold green")

        self.show_help()
        self.show_live_feed()

        while self.running:
            try:
                user_input = Prompt.ask("[bold green]Admin[/bold green]")

                if not user_input:
                    continue

                command = user_input.lower().strip()

                if command in ['quit', 'exit', 'q']:
                    console.print("[yellow]Déconnexion...[/yellow]")
                    self.running = False
                    break

                elif command == 'revoke':
                    self.revoke_user_certificate()

                elif command == 'stats':
                    self.show_statistics()

                elif command == 'registry':
                    self.show_registry()

                elif command == 'feed':
                    self.show_live_feed()

                elif command in ['help', '?']:
                    self.show_help()

                else:
                    console.print(f"[red]Commande inconnue: {command}[/red]")
                    console.print("[yellow]Tapez 'help' pour voir les commandes[/yellow]")

            except KeyboardInterrupt:
                console.print("\n[yellow]Interruption détectée...[/yellow]")
                self.running = False
                break
            except Exception as e:
                console.print(f"[red]Erreur: {e}[/red]")

    def start(self):
        """Démarre la console admin"""
        # Connexion au serveur
        if not self.connect():
            return

        # Lancer le thread d'écoute
        listen_thread = threading.Thread(
            target=self.listen_for_events,
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
    admin = AdminConsole()
    admin.start()