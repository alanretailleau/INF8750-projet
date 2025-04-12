import google.cloud.security.privateca_v1 as privateca_v1
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os
from datetime import datetime, timedelta, timezone
from google.protobuf import duration_pb2
from google.oauth2 import service_account
import json

class PKIManager:
    def __init__(self, client=None):
        # Charger les credentials de service
        credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
        if not credentials_path:
            raise ValueError("GOOGLE_APPLICATION_CREDENTIALS non défini")
        
        try:
            if os.path.exists(credentials_path):
                with open(credentials_path, 'r') as f:
                    credentials_info = json.load(f)
            else:
                credentials_info = json.loads(credentials_path)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            raise ValueError(f"Impossible de charger les credentials : {str(e)}")
        
        credentials = service_account.Credentials.from_service_account_info(
            credentials_info,
            scopes=['https://www.googleapis.com/auth/cloud-platform']
        )
        
        self.ca_service_client = client or privateca_v1.CertificateAuthorityServiceClient(credentials=credentials)
        self.cert_path = os.path.join('.certs', 'cert.pem')
        self.key_path = os.path.join('.certs', 'key.pem')

    def request_certificate(self, jwt_token: str) -> privateca_v1.Certificate:
        """
        Demande un nouveau certificat X.509 à Google Cloud CA
        """
        # Générer une paire de clés
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Configuration de la requête de certificat
        public_key = privateca_v1.PublicKey(
            key=public_key_bytes,
            format_=privateca_v1.PublicKey.KeyFormat.PEM,
        )

        subject_config = privateca_v1.CertificateConfig.SubjectConfig(
            subject=privateca_v1.Subject(common_name="temp-cert")
        )

        x509_parameters = privateca_v1.X509Parameters(
            key_usage=privateca_v1.KeyUsage(
                base_key_usage=privateca_v1.KeyUsage.KeyUsageOptions(
                    digital_signature=True
                )
            )
        )

        certificate = privateca_v1.Certificate(
            config=privateca_v1.CertificateConfig(
                public_key=public_key,
                subject_config=subject_config,
                x509_config=x509_parameters,
            ),
            lifetime=duration_pb2.Duration(seconds=86400)  # 1 jour
        )

        # Création du certificat
        request = privateca_v1.CreateCertificateRequest(
            parent=os.getenv('CA_POOL_PATH'),
            certificate_id="temp-cert",
            certificate=certificate
        )

        # Création du certificat
        response = self.ca_service_client.create_certificate(request=request)
        
        # Sauvegarde du certificat et de la clé privée
        self._save_certificate(response.pem_certificate)
        self._save_private_key(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        )

        return response

    def _save_certificate(self, cert_pem: str) -> None:
        """Sauvegarde le certificat dans le fichier .certs/cert.pem"""
        with open(self.cert_path, 'w') as f:
            f.write(cert_pem)

    def _save_private_key(self, key_pem: str) -> None:
        """Sauvegarde la clé privée dans le fichier .certs/key.pem"""
        with open(self.key_path, 'w') as f:
            f.write(key_pem)

    def save_certificate(self, cert_pem: str) -> None:
        """Méthode publique pour sauvegarder un certificat PEM"""
        self._save_certificate(cert_pem)

    def get_certificate_path(self) -> str:
        """Retourne le chemin du fichier de certificat"""
        return self.cert_path

    def get_private_key_path(self) -> str:
        """Retourne le chemin du fichier de clé privée"""
        return self.key_path

    def load_certificate(self) -> str:
        """Charge et retourne le contenu du certificat"""
        if os.path.exists(self.cert_path):
            with open(self.cert_path, 'r') as f:
                return f.read()
        return None

    def load_private_key(self) -> str:
        """Charge et retourne le contenu de la clé privée"""
        if os.path.exists(self.key_path):
            with open(self.key_path, 'r') as f:
                return f.read()
        return None

    def is_certificate_valid(self) -> bool:
        """Vérifie si le certificat actuel est toujours valide"""
        if not os.path.exists(self.cert_path):
            return False
            
        try:
            with open(self.cert_path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
                return cert.not_valid_after_utc > datetime.now(timezone.utc)
        except Exception:
            return False 