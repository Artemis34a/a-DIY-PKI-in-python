#!/usr/bin/env python3
"""
Démonstration PKI Simplifiée
Workflow complet Alice & Bob
"""

from pki import *
from rich.panel import Panel


def main():
    """Démonstration complète"""

    console.print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🔐  PKI SIMPLE - Démonstration Alice & Bob             ║
║                                                           ║
║   Workflow: Root CA → Intermediate CA → Alice & Bob      ║
║   → Signature → Vérification → Révocation                ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """, style="bold cyan")

    try:
        # ============================================
        # ÉTAPE 1: ROOT CA
        # ============================================

        console.print(Panel.fit(
            "[bold]ÉTAPE 1/7: Création de la Root CA[/bold]",
            border_style="magenta"
        ))

        root_cert, root_key = create_root_ca(
            common_name="Demo Root CA",
            organization="PKI Demo",
            key_size=4096,
            password="root123"
        )

        console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

        # ============================================
        # ÉTAPE 2: INTERMEDIATE CA
        # ============================================

        console.print(Panel.fit(
            "[bold]ÉTAPE 2/7: Création de l'Intermediate CA[/bold]",
            border_style="cyan"
        ))

        int_cert, int_key = create_intermediate_ca(
            common_name="Demo Intermediate CA",
            organization="PKI Demo",
            root_cert=root_cert,
            root_key=root_key,
            key_size=3072,
            password="int123"
        )

        console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

        # ============================================
        # ÉTAPE 3: CERTIFICATS ALICE & BOB
        # ============================================

        console.print(Panel.fit(
            "[bold]ÉTAPE 3/7: Émission des certificats Alice et Bob[/bold]",
            border_style="blue"
        ))

        console.print("\n[cyan]👤 Certificat pour Alice...[/cyan]")
        alice_cert, alice_key = issue_certificate(
            common_name="Alice",
            cert_type="client",
            issuer_cert=int_cert,
            issuer_key=int_key,
            organization="PKI Demo"
        )

        console.print("\n[cyan]👤 Certificat pour Bob...[/cyan]")
        bob_cert, bob_key = issue_certificate(
            common_name="Bob",
            cert_type="client",
            issuer_cert=int_cert,
            issuer_key=int_key,
            organization="PKI Demo"
        )

        console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

        # ============================================
        # ÉTAPE 4: ALICE SIGNE UN MESSAGE
        # ============================================

        console.print(Panel.fit(
            "[bold]ÉTAPE 4/7: Alice signe un message pour Bob[/bold]",
            border_style="green"
        ))

        message = b"Bonjour Bob ! Rendez-vous demain a 14h. - Alice"
        console.print(f"\n[yellow]Message:[/yellow] [cyan]{message.decode()}[/cyan]\n")

        signed_data = sign_message(message, alice_key, alice_cert)

        console.print(f"[green]✓ Signature: {signed_data['signature'][:32].hex()}...[/green]")

        console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

        # ============================================
        # ÉTAPE 5: BOB VÉRIFIE LA SIGNATURE
        # ============================================

        console.print(Panel.fit(
            "[bold]ÉTAPE 5/7: Bob vérifie la signature d'Alice[/bold]",
            border_style="blue"
        ))

        is_valid, msg = verify_signature(signed_data)

        if is_valid:
            console.print(f"\n[green bold]✅ {msg}[/green bold]")
            console.print(f"[green]Bob a vérifié que le message vient bien d'Alice![/green]")
            console.print(f"\n[cyan]Message reçu:[/cyan] [green]{message.decode()}[/green]")
        else:
            console.print(f"\n[red bold]❌ {msg}[/red bold]")

        console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

        # ============================================
        # ÉTAPE 6: RÉVOCATION
        # ============================================

        console.print(Panel.fit(
            "[bold]ÉTAPE 6/7: Révocation du certificat d'Alice[/bold]",
            border_style="red"
        ))

        console.print("\n[yellow]⚠️  Scénario: La clé privée d'Alice a été compromise![/yellow]\n")

        alice_serial = f"{alice_cert.serial_number:X}"
        revoke_certificate(alice_serial, reason="key_compromise")

        # Vérifier le statut OCSP
        console.print("\n[cyan]🔍 Vérification OCSP...[/cyan]")
        status = check_revocation(alice_serial)

        if status["status"] == "revoked":
            console.print(f"[red]❌ Statut: {status['message']}[/red]")
            console.print(f"[red]Raison: {status['reason']}[/red]")
            console.print(f"[red]Révoqué le: {status['revoked_at']}[/red]")

        # Essayer de vérifier à nouveau la signature
        console.print("\n[cyan]🔍 Re-vérification de la signature d'Alice...[/cyan]")
        is_valid, msg = verify_signature(signed_data)

        if not is_valid:
            console.print(f"[red bold]❌ {msg}[/red bold]")
            console.print("[red]Le certificat d'Alice est révoqué - Ne plus faire confiance![/red]")

        console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

        # ============================================
        # ÉTAPE 7: BOB ENVOIE UN MESSAGE
        # ============================================

        console.print(Panel.fit(
            "[bold]ÉTAPE 7/7: Bob envoie un message signé[/bold]",
            border_style="green"
        ))

        bob_message = b"Message de Bob: Bien recu ton message Alice. A demain!"
        console.print(f"\n[yellow]Message de Bob:[/yellow] [cyan]{bob_message.decode()}[/cyan]\n")

        bob_signed = sign_message(bob_message, bob_key, bob_cert)

        console.print("\n[cyan]🔍 Vérification par Alice...[/cyan]")
        bob_valid, bob_msg = verify_signature(bob_signed)

        if bob_valid:
            console.print(f"\n[green bold]✅ {bob_msg}[/green bold]")
            console.print(f"[green]Alice a vérifié que le message vient bien de Bob![/green]")
            console.print(f"\n[cyan]Message reçu:[/cyan] [green]{bob_message.decode()}[/green]")

        console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

        # ============================================
        # RÉSUMÉ
        # ============================================

        console.print(Panel.fit(
            "[bold magenta]📊 RÉSUMÉ[/bold magenta]",
            border_style="magenta"
        ))

        display_registry()

        console.print("\n[green bold]🎉 Démonstration terminée avec succès! 🎉[/green bold]\n")

        console.print("""
[cyan]Ce qui a été démontré:[/cyan]
  ✓ Création d'une hiérarchie PKI complète (Root → Intermediate)
  ✓ Émission de certificats clients pour Alice et Bob
  ✓ Signature numérique d'un message par Alice
  ✓ Vérification de la signature par Bob
  ✓ Révocation d'un certificat compromis
  ✓ Vérification du statut de révocation (OCSP)
  ✓ Échange bidirectionnel sécurisé

[yellow]Fichiers créés:[/yellow]
  - data/keys/ : Clés privées
  - data/certs/ : Certificats X.509
  - data/registry.json : Registre (remplace SQL)
        """)

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Démonstration interrompue[/yellow]")
    except Exception as e:
        console.print(f"\n[red]❌ Erreur: {e}[/red]")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()