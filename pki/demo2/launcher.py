#!/usr/bin/env python3
"""
Lanceur centralisé du système de messagerie PKI
Permet de démarrer tous les composants facilement
"""

import subprocess
import sys
import time
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()


def check_pki_exists():
    """Vérifie si la PKI est configurée"""
    registry_file = Path("data/registry.json")
    return registry_file.exists()


def setup_pki():
    """Lance la configuration de la PKI"""
    console.print("[cyan]Lancement de la configuration PKI...[/cyan]\n")
    try:
        subprocess.run([sys.executable, "setup.py"], check=True)
        return True
    except subprocess.CalledProcessError:
        console.print("[red]Erreur lors de la configuration[/red]")
        return False
    except KeyboardInterrupt:
        console.print("\n[yellow]Configuration annulée[/yellow]")
        return False


def launch_server():
    """Lance le serveur de messagerie"""
    console.print("[green]Lancement du serveur...[/green]")
    try:
        if sys.platform == "win32":
            # Windows
            subprocess.Popen(
                ["start", "cmd", "/k", sys.executable, "messaging_server.py"],
                shell=True
            )
        elif sys.platform == "darwin":
            # macOS
            subprocess.Popen([
                "osascript", "-e",
                f'tell app "Terminal" to do script "cd {Path.cwd()} && {sys.executable} messaging_server.py"'
            ])
        else:
            # Linux
            terminals = [
                ["gnome-terminal", "--", sys.executable, "messaging_server.py"],
                ["konsole", "-e", sys.executable, "messaging_server.py"],
                ["xterm", "-e", sys.executable, "messaging_server.py"],
            ]

            for terminal in terminals:
                try:
                    subprocess.Popen(terminal)
                    break
                except FileNotFoundError:
                    continue

        console.print("[green]✓ Serveur lancé dans une nouvelle fenêtre[/green]")
        time.sleep(2)  # Attendre que le serveur démarre
        return True

    except Exception as e:
        console.print(f"[red]Erreur lancement serveur: {e}[/red]")
        return False


def launch_client(name, script):
    """Lance un client dans une nouvelle fenêtre"""
    console.print(f"[cyan]Lancement de {name}...[/cyan]")
    try:
        if sys.platform == "win32":
            # Windows
            subprocess.Popen(
                ["start", "cmd", "/k", sys.executable, script],
                shell=True
            )
        elif sys.platform == "darwin":
            # macOS
            subprocess.Popen([
                "osascript", "-e",
                f'tell app "Terminal" to do script "cd {Path.cwd()} && {sys.executable} {script}"'
            ])
        else:
            # Linux
            terminals = [
                ["gnome-terminal", "--", sys.executable, script],
                ["konsole", "-e", sys.executable, script],
                ["xterm", "-e", sys.executable, script],
            ]

            for terminal in terminals:
                try:
                    subprocess.Popen(terminal)
                    break
                except FileNotFoundError:
                    continue

        console.print(f"[green]✓ {name} lancé dans une nouvelle fenêtre[/green]")
        time.sleep(1)
        return True

    except Exception as e:
        console.print(f"[red]Erreur lancement {name}: {e}[/red]")
        return False


def launch_all():
    """Lance tous les composants"""
    console.print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🚀 LANCEUR SYSTÈME DE MESSAGERIE PKI                   ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """, style="bold green")

    # Vérifier si la PKI existe
    if not check_pki_exists():
        console.print("[yellow]⚠️  Aucune PKI détectée![/yellow]\n")
        console.print("[cyan]Configuration de la PKI nécessaire...[/cyan]\n")

        if not setup_pki():
            return

        console.print("\n[green]✓ PKI configurée avec succès![/green]\n")
        time.sleep(2)

    console.print("[cyan]Lancement de tous les composants...[/cyan]\n")

    # Lancer le serveur
    if not launch_server():
        console.print("[red]Impossible de lancer le serveur[/red]")
        return

    time.sleep(2)

    # Lancer Alice
    launch_client("Alice", "client_alice.py")
    time.sleep(1)

    # Lancer Bob
    launch_client("Bob", "client_bob.py")
    time.sleep(1)

    # Lancer Admin
    launch_client("Admin", "admin_console.py")

    console.print("\n" + "=" * 60)
    console.print(Panel.fit(
        "[bold green]✅ SYSTÈME DÉMARRÉ[/bold green]",
        border_style="green"
    ))

    console.print("""
[cyan]Tous les composants ont été lancés dans des fenêtres séparées:[/cyan]
  • Serveur de messagerie
  • Console Alice
  • Console Bob
  • Console Admin

[yellow]Pour arrêter le système:[/yellow]
  • Fermez chaque fenêtre individuellement
  • Ou utilisez Ctrl+C dans chaque terminal

[cyan]Astuce:[/cyan]
  • Alice et Bob peuvent s'échanger des messages
  • Admin peut voir le flux en temps réel et révoquer des certificats
    """)


def manual_launch():
    """Mode de lancement manuel"""
    console.print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🛠️  LANCEUR MANUEL                                     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """, style="bold cyan")

    # Vérifier PKI
    if not check_pki_exists():
        console.print("[yellow]⚠️  Aucune PKI détectée![/yellow]\n")
        if Prompt.ask("Configurer la PKI maintenant?", choices=["oui", "non"]) == "oui":
            if not setup_pki():
                return

    console.print("\n[cyan]Que voulez-vous lancer?[/cyan]\n")
    console.print("1. Serveur uniquement")
    console.print("2. Alice uniquement")
    console.print("3. Bob uniquement")
    console.print("4. Admin uniquement")
    console.print("5. Tout lancer")
    console.print("6. Configurer/Reconfigurer la PKI")
    console.print("7. Quitter")

    choice = Prompt.ask("Votre choix", choices=["1", "2", "3", "4", "5", "6", "7"])

    if choice == "1":
        launch_server()
    elif choice == "2":
        launch_client("Alice", "client_alice.py")
    elif choice == "3":
        launch_client("Bob", "client_bob.py")
    elif choice == "4":
        launch_client("Admin", "admin_console.py")
    elif choice == "5":
        launch_all()
    elif choice == "6":
        setup_pki()
    elif choice == "7":
        console.print("[yellow]Au revoir![/yellow]")
        return


def main():
    """Point d'entrée principal"""
    try:
        if len(sys.argv) > 1:
            if sys.argv[1] == "--all":
                launch_all()
            elif sys.argv[1] == "--setup":
                setup_pki()
            elif sys.argv[1] == "--server":
                launch_server()
            elif sys.argv[1] == "--alice":
                launch_client("Alice", "client_alice.py")
            elif sys.argv[1] == "--bob":
                launch_client("Bob", "client_bob.py")
            elif sys.argv[1] == "--admin":
                launch_client("Admin", "admin_console.py")
            else:
                console.print("[red]Argument invalide[/red]")
                console.print("\n[cyan]Utilisation:[/cyan]")
                console.print("  python launcher.py [--all|--setup|--server|--alice|--bob|--admin]")
        else:
            # Mode interactif
            console.print("\n[cyan]Mode:[/cyan]")
            console.print("  1. Lancer tout automatiquement")
            console.print("  2. Lancement manuel (choisir les composants)")

            mode = Prompt.ask("Votre choix", choices=["1", "2"], default="1")

            if mode == "1":
                launch_all()
            else:
                manual_launch()

    except KeyboardInterrupt:
        console.print("\n[yellow]Interruption détectée[/yellow]")
    except Exception as e:
        console.print(f"[red]Erreur: {e}[/red]")


if __name__ == "__main__":
    main()