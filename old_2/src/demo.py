#!/usr/bin/env python3
"""
Démonstration COMPLÈTE du système PKI
======================================

Parties 1-7 : Workflow complet de A à Z
- Root CA
- Intermediate CA
- RA (vérification identité)
- Émission certificats clients
- Révocation
- Signature & Vérification
- Validation CIAN
- Simulation Alice & Bob

"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from pki import utils, config
from pki.models import DistinguishedName
from pki.root_ca import RootCAManager
from pki.intermediate_ca import IntermediateCAManager
from pki.registration_authority import RegistrationAuthority
from pki.certificate_issuer import CertificateIssuer
from pki.revocation_manager import RevocationManager
from pki.signature_manager import SignatureManager
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def demo_full_pki_workflow():
    """Workflow PKI complet de A à Z"""

    utils.print_header("🚀 DÉMONSTRATION PKI COMPLÈTE")

    # ============================================
    # ÉTAPE 1: CRÉER LA ROOT CA
    # ============================================

    utils.print_header("👑 ÉTAPE 1/8 : Création de la Root CA")

    root_ca = RootCAManager()

    root_dn = DistinguishedName(
        common_name="Demo Root CA",
        organization="Demo PKI Organization",
        organizational_unit="Certificate Authority",
        country="CM",
        state="Adamaoua",
        locality="Ngaoundere"
    )

    root_cert, root_key, root_cert_path, root_key_path = root_ca.create_root_ca(
        dn=root_dn,
        key_size=4096,
        validity_days=7300,
        password="RootCAPassword123!"
    )

    utils.console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

    # ============================================
    # ÉTAPE 2: CRÉER L'INTERMEDIATE CA
    # ============================================

    utils.print_header("🌐 ÉTAPE 2/8 : Création de l'Intermediate CA")

    intermediate_ca = IntermediateCAManager()

    int_dn = DistinguishedName(
        common_name="Demo Intermediate CA",
        organization="Demo PKI Organization",
        organizational_unit="Intermediate CA",
        country="CM",
        state="Adamaoua",
        locality="Ngaoundere"
    )

    int_cert, int_key, int_cert_path, int_key_path = intermediate_ca.create_intermediate_ca(
        dn=int_dn,
        root_cert=root_cert,
        root_key=root_key,
        key_size=3072,
        validity_days=3650,
        password="IntermediateCAPassword123!"
    )

    # Construire la chaîne
    ca_chain = intermediate_ca.build_cert_chain(int_cert, root_cert)

    # Valider la chaîne
    intermediate_ca.validate_chain(int_cert, root_cert)

    utils.console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

    # ============================================
    # ÉTAPE 3: ÉMETTRE CERTIFICATS POUR ALICE ET BOB
    # ============================================

    utils.print_header("👥 ÉTAPE 3/8 : Émission des certificats Alice et Bob")

    issuer = CertificateIssuer()

    # Certificat pour Alice
    utils.print_info("\n📝 Émission du certificat pour Alice...")
    alice_cert, alice_cert_path = issuer.issue_client_certificate(
        user_name="Alice",
        organization="Demo PKI Organization",
        issuer_cert=int_cert,
        issuer_key=int_key,
        email="alice@demo.pki"
    )

    # Charger la clé d'Alice
    alice_key_path = config.get_key_path("alice", "private")
    alice_key = issuer.key_gen.load_private_key(alice_key_path)

    utils.print_success(f"✅ Certificat Alice émis: {alice_cert_path.name}")

    # Certificat pour Bob
    utils.print_info("\n📝 Émission du certificat pour Bob...")
    bob_cert, bob_cert_path = issuer.issue_client_certificate(
        user_name="Bob",
        organization="Demo PKI Organization",
        issuer_cert=int_cert,
        issuer_key=int_key,
        email="bob@demo.pki"
    )

    # Charger la clé de Bob
    bob_key_path = config.get_key_path("bob", "private")
    bob_key = issuer.key_gen.load_private_key(bob_key_path)

    utils.print_success(f"✅ Certificat Bob émis: {bob_cert_path.name}")

    utils.console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

    # ============================================
    # ÉTAPE 4: ALICE SIGNE UN MESSAGE POUR BOB
    # ============================================

    utils.print_header("✍️  ÉTAPE 4/8 : Alice signe un message pour Bob")

    sig_manager = SignatureManager()

    message = b"Bonjour Bob ! Ceci est un message confidentiel d'Alice. Rendez-vous demain a 14h."

    utils.print_info(f"Message original:\n[cyan]{message.decode()}[/cyan]\n")

    signed_data = sig_manager.sign_message(
        message=message,
        private_key=alice_key,
        certificate=alice_cert
    )

    utils.print_success("✅ Message signé par Alice")
    utils.print_info(f"Signature: {utils.bytes_to_hex(signed_data['signature'][:32])}...")

    utils.console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

    # ============================================
    # ÉTAPE 5: BOB VÉRIFIE LA SIGNATURE
    # ============================================

    utils.print_header("🔍 ÉTAPE 5/8 : Bob vérifie la signature d'Alice")

    # Bob vérifie avec la chaîne de confiance
    trust_chain = [root_cert, int_cert]

    is_valid, verify_report = sig_manager.verify_signature(
        signed_data=signed_data,
        trust_chain=trust_chain
    )

    if is_valid:
        utils.print_success("✅ Bob a vérifié que le message vient bien d'Alice")
        utils.print_info(f"Message reçu:\n[green]{message.decode()}[/green]")
    else:
        utils.print_error("❌ Signature invalide !")

    utils.console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

    # ============================================
    # ÉTAPE 6: VALIDATION CIAN
    # ============================================

    utils.print_header("🔐 ÉTAPE 6/8 : Validation des principes CIAN")

    cian_report = sig_manager.validate_cian(
        signed_data=signed_data,
        trust_chain=trust_chain
    )

    utils.console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

    # ============================================
    # ÉTAPE 7: RÉVOCATION DU CERTIFICAT D'ALICE
    # ============================================

    utils.print_header("🚫 ÉTAPE 7/8 : Révocation du certificat d'Alice")

    utils.print_warning("⚠️  Scénario: La clé d'Alice a été compromise!")

    rev_manager = RevocationManager()

    # Révoquer le certificat d'Alice
    alice_serial = f"{alice_cert.serial_number:X}"
    rev_manager.revoke_certificate(alice_serial, reason="key_compromise")

    # Générer une CRL
    crl, crl_path = rev_manager.generate_crl(
        issuer_cert=int_cert,
        issuer_key=int_key
    )

    # Vérification OCSP
    utils.print_info("\n🔍 Vérification OCSP du certificat d'Alice...")
    ocsp_response = rev_manager.ocsp_check(alice_serial)
    rev_manager.display_ocsp_response(ocsp_response)

    # Vérifier dans la CRL
    utils.print_info("\n📋 Vérification dans la CRL...")
    is_revoked = rev_manager.check_certificate_in_crl(alice_cert, crl)

    if is_revoked:
        utils.print_error("❌ Le certificat d'Alice est RÉVOQUÉ - Ne plus accepter ses signatures!")

    utils.console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")

    # ============================================
    # ÉTAPE 8: BOB ENVOIE UN MESSAGE À ALICE
    # ============================================

    utils.print_header("✍️  ÉTAPE 8/8 : Bob envoie un message signé")

    bob_message = b"Message de Bob a Alice: J'ai bien recu ton message. RDV confirme pour 14h demain."

    utils.print_info(f"Message de Bob:\n[cyan]{bob_message.decode()}[/cyan]\n")

    bob_signed_data = sig_manager.sign_message(
        message=bob_message,
        private_key=bob_key,
        certificate=bob_cert
    )

    utils.print_success("✅ Message signé par Bob")

    # Vérification
    utils.print_info("\n🔍 Alice vérifie la signature de Bob...")

    bob_valid, bob_report = sig_manager.verify_signature(
        signed_data=bob_signed_data,
        trust_chain=trust_chain
    )

    if bob_valid:
        utils.print_success("✅ Alice a vérifié que le message vient bien de Bob")
        utils.print_info(f"Message reçu:\n[green]{bob_message.decode()}[/green]")

    # CIAN pour Bob
    utils.print_info("\n🔐 Validation CIAN pour le message de Bob...")
    bob_cian = sig_manager.validate_cian(bob_signed_data, trust_chain)

    # ============================================
    # RÉSUMÉ FINAL
    # ============================================

    utils.print_header("📊 RÉSUMÉ DE LA DÉMONSTRATION")

    summary_table = utils.create_table(
        "Résumé du workflow PKI complet",
        ["Étape", "Statut", "Description"]
    )

    summary_table.add_row(
        "1️⃣ Root CA",
        "[green]✅ OK[/green]",
        "Root CA créée et valide"
    )

    summary_table.add_row(
        "2️⃣ Intermediate CA",
        "[green]✅ OK[/green]",
        "Intermediate CA signée par Root"
    )

    summary_table.add_row(
        "3️⃣ Certificats",
        "[green]✅ OK[/green]",
        "Alice et Bob ont leurs certificats"
    )

    summary_table.add_row(
        "4️⃣ Signature Alice",
        "[green]✅ OK[/green]",
        "Message signé par Alice"
    )

    summary_table.add_row(
        "5️⃣ Vérification",
        "[green]✅ OK[/green]" if is_valid else "[red]❌ KO[/red]",
        "Bob a vérifié la signature"
    )

    summary_table.add_row(
        "6️⃣ Validation CIAN",
        "[green]✅ OK[/green]" if cian_report["overall"] else "[red]❌ KO[/red]",
        "Principes CIAN validés"
    )

    summary_table.add_row(
        "7️⃣ Révocation",
        "[green]✅ OK[/green]",
        "Certificat Alice révoqué (CRL + OCSP)"
    )

    summary_table.add_row(
        "8️⃣ Signature Bob",
        "[green]✅ OK[/green]" if bob_valid else "[red]❌ KO[/red]",
        "Message Bob vérifié par Alice"
    )

    utils.console.print(summary_table)

    # Statistiques finales
    from pki.database import pki_db

    utils.print_info("\n📊 Statistiques finales:")
    stats = pki_db.get_statistics()

    stats_table = utils.create_table("Statistiques PKI", ["Métrique", "Valeur"])
    stats_table.add_row("Total certificats", str(stats['total_certificates']))
    stats_table.add_row("Certificats actifs", f"[green]{stats['active_certificates']}[/green]")
    stats_table.add_row("Certificats révoqués", f"[red]{stats['revoked_certificates']}[/red]")

    utils.console.print(stats_table)

    utils.print_success("\n🎉 Démonstration complète terminée avec succès! 🎉\n")


def main():
    """Fonction principale"""

    # Bannière
    utils.console.print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🔐  PKI PROJECT - DÉMONSTRATION COMPLÈTE                   ║
║                                                               ║
║   Workflow complet : Root CA → Intermediate CA → Certificats ║
║   → Signature → Vérification → Révocation → CIAN             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """, style="bold cyan")

    utils.print_info("""
Cette démonstration va exécuter un workflow PKI complet de A à Z:

1. Création d'une Root CA
2. Création d'une Intermediate CA
3. Émission de certificats pour Alice et Bob
4. Alice signe un message pour Bob
5. Bob vérifie la signature d'Alice
6. Validation des principes CIAN
7. Révocation du certificat d'Alice
8. Bob envoie un message signé à Alice

Durée estimée: 3-5 minutes
    """)

    if not utils.confirm_action("Voulez-vous lancer la démonstration complète ?", default=True):
        utils.print_info("Démonstration annulée.")
        return

    try:
        demo_full_pki_workflow()
    except KeyboardInterrupt:
        utils.print_warning("\n\n⚠️  Démonstration interrompue par l'utilisateur")
    except Exception as e:
        utils.print_error(f"\n❌ Erreur: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()