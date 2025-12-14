#!/usr/bin/env python3
"""
Configuration initiale de la PKI
Crée la hiérarchie CA et les certificats pour Alice et Bob
"""




from pki.pki import *
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
import sys


def setup_pki_interactive():
    """Configuration interactive de la PKI"""

    console.print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🔐 CONFIGURATION PKI - Messagerie Sécurisée            ║
║                                                           ║
║   Cette configuration va créer:                          ║
║   • Root CA (Autorité de certification racine)           ║
║   • Intermediate CA (Autorité intermédiaire)             ║
║   • Certificats pour Alice et Bob                        ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """, style="bold cyan")

    # Vérifier si une PKI existe déjà
    if REGISTRY_FILE.exists():
        console.print("[yellow]⚠️  Une PKI existe déjà![/yellow]")
        if not Confirm.ask("Voulez-vous la réinitialiser?", default=False):
            console.print("[red]Configuration annulée[/red]")
            return

        # Réinitialiser
        import shutil
        shutil.rmtree(DATA_DIR)
        for d in [DATA_DIR, KEYS_DIR, CERTS_DIR]:
            d.mkdir(exist_ok=True)
        console.print("[green]✓ PKI réinitialisée[/green]\n")

    try:
        # ============================================
        # ÉTAPE 1: Informations de l'organisation
        # ============================================

        console.print(Panel.fit(
            "[bold]ÉTAPE 1/5: Informations de l'organisation[/bold]",
            border_style="cyan"
        ))

        org_name = Prompt.ask(
            "Nom de l'organisation",
            default="Demo Organization"
        )

        console.print()

        # ============================================
        # ÉTAPE 2: ROOT CA
        # ============================================

        console.print(Panel.fit(
            "[bold]ÉTAPE 2/5: Création de la Root CA[/bold]",
            border_style="magenta"
        ))

        root_cn = Prompt.ask(
            "Nom de la Root CA",
            default=f"{org_name} Root CA"
        )

        root_password = Prompt.ask(
            "Mot de passe pour la clé Root CA",
            password=True,
            default="root123"
        )

        console.print()

        root_cert, root_key = create_root_ca(
            common_name=root_cn,
            organization=org_name,
            key_size=4096,
            password=root_password
        )

        console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]\n")

        # ============================================
        # ÉTAPE 3: INTERMEDIATE CA
        # ============================================

        console.print(Panel.fit(
            "[bold]ÉTAPE 3/5: Création de l'Intermediate CA[/bold]",
            border_style="cyan"
        ))

        int_cn = Prompt.ask(
            "Nom de l'Intermediate CA",
            default=f"{org_name} Intermediate CA"
        )

        int_password = Prompt.ask(
            "Mot de passe pour la clé Intermediate CA",
            password=True,
            default="int123"
        )

        console.print()

        int_cert, int_key = create_intermediate_ca(
            common_name=int_cn,
            organization=org_name,
            root_cert=root_cert,
            root_key=root_key,
            key_size=3072,
            password=int_password
        )

        console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]\n")

        # ============================================
        # ÉTAPE 4: CERTIFICAT ALICE
        # ============================================

        console.print(Panel.fit(
            "[bold]ÉTAPE 4/5: Création du certificat pour Alice[/bold]",
            border_style="blue"
        ))

        alice_name = Prompt.ask(
            "Nom complet d'Alice",
            default="Alice"
        )

        console.print()

        alice_cert, alice_key = issue_certificate(
            common_name=alice_name,
            cert_type="client",
            issuer_cert=int_cert,
            issuer_key=int_key,
            organization=org_name,
            validity_days=365
        )

        console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]\n")

        # ============================================
        # ÉTAPE 5: CERTIFICAT BOB
        # ============================================

        console.print(Panel.fit(
            "[bold]ÉTAPE 5/5: Création du certificat pour Bob[/bold]",
            border_style="blue"
        ))

        bob_name = Prompt.ask(
            "Nom complet de Bob",
            default="Bob"
        )

        console.print()

        bob_cert, bob_key = issue_certificate(
            common_name=bob_name,
            cert_type="client",
            issuer_cert=int_cert,
            issuer_key=int_key,
            organization=org_name,
            validity_days=365
        )

        console.print("\n" + "=" * 60 + "\n")

        # ============================================
        # RÉSUMÉ
        # ============================================

        console.print(Panel.fit(
            "[bold green]✅ CONFIGURATION TERMINÉE[/bold green]",
            border_style="green"
        ))

        console.print("\n[cyan]PKI créée avec succès![/cyan]\n")

        display_registry()

        console.print("\n[yellow]📂 Fichiers créés:[/yellow]")
        console.print(f"  • {KEYS_DIR}/root_ca_key.pem")
        console.print(f"  • {KEYS_DIR}/intermediate_ca_key.pem")
        console.print(f"  • {KEYS_DIR}/alice_key.pem")
        console.print(f"  • {KEYS_DIR}/bob_key.pem")
        console.print(f"  • {CERTS_DIR}/root_ca_cert.pem")
        console.print(f"  • {CERTS_DIR}/intermediate_ca_cert.pem")
        console.print(f"  • {CERTS_DIR}/alice_cert.pem")
        console.print(f"  • {CERTS_DIR}/bob_cert.pem")
        console.print(f"  • {REGISTRY_FILE}")

        console.print("\n[green bold]🎉 La PKI est prête à être utilisée![/green bold]\n")

        console.print("[cyan]Prochaines étapes:[/cyan]")
        console.print("  1. Lancez le serveur: [bold]python messaging_server.py[/bold]")
        console.print("  2. Lancez Alice: [bold]python client_alice.py[/bold]")
        console.print("  3. Lancez Bob: [bold]python client_bob.py[/bold]")
        console.print("  4. Lancez Admin: [bold]python admin_console.py[/bold]")
        console.print()

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Configuration interrompue[/yellow]")
    except Exception as e:
        console.print(f"\n[red]❌ Erreur: {e}[/red]")
        import traceback
        traceback.print_exc()


def setup_pki_automatic():
    """Configuration automatique (non-interactive)"""

    console.print("[cyan]Configuration automatique de la PKI...[/cyan]\n")

    try:
        # Réinitialiser si existe
        if REGISTRY_FILE.exists():
            import shutil
            shutil.rmtree(DATA_DIR)
            for d in [DATA_DIR, KEYS_DIR, CERTS_DIR]:
                d.mkdir(exist_ok=True)

        # Root CA
        root_cert, root_key = create_root_ca(
            common_name="Demo Root CA",
            organization="PKI Demo",
            key_size=4096,
            password="root123"
        )

        # Intermediate CA
        int_cert, int_key = create_intermediate_ca(
            common_name="Demo Intermediate CA",
            organization="PKI Demo",
            root_cert=root_cert,
            root_key=root_key,
            key_size=3072,
            password="int123"
        )

        # Certificat Alice
        alice_cert, alice_key = issue_certificate(
            common_name="Alice",
            cert_type="client",
            issuer_cert=int_cert,
            issuer_key=int_key,
            organization="PKI Demo"
        )

        # Certificat Bob
        bob_cert, bob_key = issue_certificate(
            common_name="Bob",
            cert_type="client",
            issuer_cert=int_cert,
            issuer_key=int_key,
            organization="PKI Demo"
        )

        console.print("\n[green bold]✅ PKI configurée automatiquement![/green bold]\n")
        display_registry()

    except Exception as e:
        console.print(f"[red]Erreur: {e}[/red]")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Vérifier les arguments
    if len(sys.argv) > 1 and sys.argv[1] == '--auto':
        setup_pki_automatic()
    else:
        setup_pki_interactive()