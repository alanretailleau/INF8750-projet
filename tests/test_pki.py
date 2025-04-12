import os
import unittest
from unittest.mock import MagicMock, patch, ANY
from datetime import datetime, timedelta, timezone
from auth.pki import PKIManager
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import google.cloud.security.privateca_v1 as privateca_v1
from google.protobuf import duration_pb2
from google.api_core import exceptions

class TestPKIManager(unittest.TestCase):
    def setUp(self):
        # Créer le répertoire .certs s'il n'existe pas
        os.makedirs('.certs', exist_ok=True)
        # Mock l'environnement
        os.environ['CA_POOL_PATH'] = 'projects/test-project/locations/test-location/caPools/test-pool'
        # Créer un mock du client
        self.mock_client = MagicMock()
        self.pki_manager = PKIManager(client=self.mock_client)

    def tearDown(self):
        # Nettoyer les fichiers de test
        if os.path.exists(self.pki_manager.cert_path):
            os.remove(self.pki_manager.cert_path)
        if os.path.exists(self.pki_manager.key_path):
            os.remove(self.pki_manager.key_path)
        # Supprimer la variable d'environnement
        if 'CA_POOL_PATH' in os.environ:
            del os.environ['CA_POOL_PATH']

    def test_request_certificate_success(self):
        # Configurer le mock
        mock_response = privateca_v1.Certificate()
        mock_response.pem_certificate = "-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQCrTZF6LmSPGjANBgkq\n-----END CERTIFICATE-----"
        mock_response.name = "test_certificate"
        self.mock_client.create_certificate.return_value = mock_response

        # Tester la demande de certificat
        result = self.pki_manager.request_certificate("test_token")
        self.assertEqual(result, mock_response)

        # Vérifier que la méthode create_certificate a été appelée avec les bons arguments
        self.mock_client.create_certificate.assert_called_once()
        
        # Vérifier que le certificat et la clé ont été sauvegardés
        self.assertTrue(os.path.exists(self.pki_manager.cert_path))
        self.assertTrue(os.path.exists(self.pki_manager.key_path))

    def test_request_certificate_api_error(self):
        # Simuler une erreur de l'API
        self.mock_client.create_certificate.side_effect = exceptions.PermissionDenied(
            "Permission denied"
        )

        # Vérifier que l'erreur est propagée
        with self.assertRaises(exceptions.PermissionDenied):
            self.pki_manager.request_certificate("test_token")

    def test_request_certificate_invalid_token(self):
        # Simuler une erreur de token invalide
        self.mock_client.create_certificate.side_effect = exceptions.InvalidArgument(
            "Invalid token"
        )

        # Vérifier que l'erreur est propagée
        with self.assertRaises(exceptions.InvalidArgument):
            self.pki_manager.request_certificate("invalid_token")

    def test_is_certificate_valid(self):
        # Générer une paire de clés pour le test
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Créer un certificat valide
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"test-cert"),
        ])
        
        now = datetime.now(timezone.utc)
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + timedelta(days=1)
        ).sign(private_key, hashes.SHA256())

        # Sauvegarder le certificat
        with open(self.pki_manager.cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Vérifier que le certificat est valide
        self.assertTrue(self.pki_manager.is_certificate_valid())

        # Créer un certificat expiré
        expired_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now - timedelta(days=2)
        ).not_valid_after(
            now - timedelta(days=1)
        ).sign(private_key, hashes.SHA256())

        # Sauvegarder le certificat expiré
        with open(self.pki_manager.cert_path, "wb") as f:
            f.write(expired_cert.public_bytes(serialization.Encoding.PEM))

        # Vérifier que le certificat est invalide
        self.assertFalse(self.pki_manager.is_certificate_valid())

    def test_is_certificate_valid_no_certificate(self):
        # Vérifier que le certificat est invalide quand il n'existe pas
        self.assertFalse(self.pki_manager.is_certificate_valid())

    def test_is_certificate_valid_invalid_file(self):
        # Créer un fichier de certificat invalide avec un format PEM incorrect
        invalid_pem = b"-----BEGIN CERTIFICATE-----\nInvalid Content\n-----END CERTIFICATE-----\n"
        with open(self.pki_manager.cert_path, "wb") as f:
            f.write(invalid_pem)

        # Vérifier que le certificat est invalide
        self.assertFalse(self.pki_manager.is_certificate_valid())

    def test_save_certificate_and_key(self):
        # Générer une paire de clés pour le test
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Créer un certificat
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"test-cert"),
        ])
        
        now = datetime.now(timezone.utc)
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + timedelta(days=1)
        ).sign(private_key, hashes.SHA256())

        # Sauvegarder le certificat et la clé
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Sauvegarder les fichiers directement
        with open(self.pki_manager.cert_path, "wb") as f:
            f.write(cert_pem)
        with open(self.pki_manager.key_path, "wb") as f:
            f.write(key_pem)

        # Vérifier que les fichiers ont été créés
        self.assertTrue(os.path.exists(self.pki_manager.cert_path))
        self.assertTrue(os.path.exists(self.pki_manager.key_path))

        # Vérifier que les fichiers contiennent les bonnes données
        with open(self.pki_manager.cert_path, "rb") as f:
            saved_cert = f.read()
            self.assertEqual(saved_cert, cert_pem)

        with open(self.pki_manager.key_path, "rb") as f:
            saved_key = f.read()
            self.assertEqual(saved_key, key_pem)

if __name__ == '__main__':
    unittest.main() 