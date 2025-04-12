import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import os
import base64
import hashlib
import json
from typing import Optional, Dict, Any, Union

class RequestSigner:
    def __init__(self):
        self.cert_path = os.path.join('.certs', 'cert.pem')
        self.key_path = os.path.join('.certs', 'key.pem')

    def sign_request(self, method: str, url: str, headers: dict = None, data: str = None) -> dict:
        """
        Signe une requête avec le certificat X.509 actuel
        """
        if not os.path.exists(self.key_path):
            raise FileNotFoundError("Clé privée non trouvée")

        # Chargement de la clé privée
        with open(self.key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        # Création de la signature
        message = f"{method}\n{url}\n{data if data else ''}"
        signature = private_key.sign(
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Encodage de la signature en base64
        signature_b64 = base64.b64encode(signature).decode()

        # Ajout des headers de signature
        headers = headers or {}
        headers.update({
            'X-509-Signature': signature_b64,
            'X-509-Certificate': self._get_certificate_pem()
        })

        return headers

    def _get_certificate_pem(self) -> str:
        """Récupère le certificat au format PEM"""
        with open(self.cert_path, 'r') as f:
            return f.read().strip()

    def make_signed_request(self, method: str, url: str, jwt_token: Optional[str] = None, 
                           headers: Optional[Dict[str, str]] = None, 
                           data: Optional[Union[Dict, str]] = None,
                           params: Optional[Dict] = None) -> requests.Response:
        """
        Effectue une requête HTTP signée avec le certificat actuel
        
        Args:
            method: Méthode HTTP (GET, POST, etc.)
            url: URL de destination
            jwt_token: JWT token à inclure dans l'en-tête Authorization (optionnel)
            headers: En-têtes supplémentaires (optionnel)
            data: Données à envoyer avec la requête (optionnel)
            params: Paramètres de requête (optionnel)
            
        Returns:
            La réponse HTTP
        """
        # Préparation des en-têtes
        headers = headers or {}
        
        # Ajout du JWT token si fourni
        if jwt_token:
            headers['Authorization'] = f'Bearer {jwt_token}'
        
        # Conversion des données en chaîne JSON si nécessaire
        data_str = None
        if data:
            if isinstance(data, dict):
                data_str = json.dumps(data)
            else:
                data_str = str(data)
        
        # Signature de la requête
        signed_headers = self.sign_request(method, url, headers, data_str)
        
        # Exécution de la requête HTTP
        return requests.request(
            method=method,
            url=url,
            headers=signed_headers,
            data=data_str,
            params=params
        )

    def verify_request(self, method: str, url: str, signature: str, data: str = None) -> bool:
        """
        Vérifie la signature d'une requête entrante
        """
        if not os.path.exists(self.cert_path):
            return False

        # Chargement du certificat
        with open(self.cert_path, 'rb') as f:
            cert = serialization.load_pem_x509_certificate(f.read())

        # Vérification de la signature
        try:
            cert.public_key().verify(
                base64.b64decode(signature),
                f"{method}\n{url}\n{data if data else ''}".encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False 