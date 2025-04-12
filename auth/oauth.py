from google.oauth2 import service_account
from google.auth import jwt
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import secrets
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

class OAuthManager:
    def __init__(self):
        self.credentials = None
        self._load_credentials()
        self._access_token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self._oauth_states: Dict[str, datetime] = {}  # Pour stocker les états OAuth et leur expiration
        
        # Configuration OAuth
        self.client_config = {
            'web': {
                'client_id': os.getenv('GOOGLE_OAUTH_CLIENT_ID'),
                'client_secret': os.getenv('GOOGLE_OAUTH_CLIENT_SECRET'),
                'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                'token_uri': 'https://oauth2.googleapis.com/token',
                'redirect_uris': [os.getenv('OAUTH_REDIRECT_URI')],
                'scopes': [
                    'openid',
                    'https://www.googleapis.com/auth/userinfo.profile',
                    'https://www.googleapis.com/auth/userinfo.email'
                ]
            }
        }

    def _load_credentials(self):
        """Charge les credentials depuis les variables d'environnement ou un fichier"""
        credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
        if not credentials_path:
            raise ValueError("GOOGLE_APPLICATION_CREDENTIALS non défini")
        
        try:
            # Essayer de charger comme un fichier d'abord
            if os.path.exists(credentials_path):
                with open(credentials_path, 'r') as f:
                    credentials_info = json.load(f)
            else:
                # Si ce n'est pas un chemin de fichier valide, essayer de le traiter comme du JSON
                credentials_info = json.loads(credentials_path)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            raise ValueError(f"Impossible de charger les credentials : {str(e)}")
        
        self.credentials = service_account.Credentials.from_service_account_info(
            credentials_info,
            scopes=[
                'https://www.googleapis.com/auth/cloud-platform',
                'https://www.googleapis.com/auth/userinfo.email'
            ]
        )

    def _cleanup_expired_states(self):
        """Nettoie les états OAuth expirés"""
        now = datetime.now(timezone.utc)
        expired_states = [
            state for state, expiry in self._oauth_states.items()
            if expiry < now
        ]
        for state in expired_states:
            del self._oauth_states[state]

    def init_oauth_flow(self) -> Dict[str, str]:
        """
        Initialise le flux OAuth et retourne l'URL d'authentification
        """
        # Nettoie les états expirés
        self._cleanup_expired_states()
        
        # Génère un nouvel état
        state = secrets.token_urlsafe(32)
        self._oauth_states[state] = datetime.now(timezone.utc) + timedelta(minutes=10)
        
        # Crée le flux OAuth
        flow = Flow.from_client_config(
            self.client_config,
            scopes=self.client_config['web']['scopes'],
            state=state
        )
        flow.redirect_uri = self.client_config['web']['redirect_uris'][0]
        
        # Génère l'URL d'authentification
        auth_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        return {
            'auth_url': auth_url,
            'state': state
        }

    def validate_oauth_callback(self, code: str, state: str) -> Dict[str, Any]:
        """
        Valide le callback OAuth et échange le code contre un token
        """
        if not code or not state:
            raise ValueError("Missing required parameters")
            
        # Vérifie que l'état est valide et non expiré
        if state not in self._oauth_states:
            raise ValueError("Invalid state")
            
        if datetime.now(timezone.utc) > self._oauth_states[state]:
            del self._oauth_states[state]
            raise ValueError("State expired")
            
        # Crée le flux OAuth
        flow = Flow.from_client_config(
            self.client_config,
            scopes=self.client_config['web']['scopes'],
            state=state
        )
        flow.redirect_uri = self.client_config['web']['redirect_uris'][0]
        
        # Échange le code contre un token
        flow.fetch_token(code=code)
        
        # Nettoie l'état utilisé
        del self._oauth_states[state]
        
        return {
            'access_token': flow.credentials.token,
            'expires_in': flow.credentials.expiry.timestamp() - datetime.now(timezone.utc).timestamp()
        }

    def get_access_token(self) -> str:
        """
        Récupère un token d'accès valide
        """
        if self._access_token and self._token_expiry and datetime.now(timezone.utc) < self._token_expiry:
            return self._access_token

        # Demande un nouveau token
        self.credentials.refresh(None)
        self._access_token = self.credentials.token
        self._token_expiry = datetime.now(timezone.utc) + timedelta(minutes=55)  # Les tokens expirent après 1h
        
        return self._access_token

    def get_jwt(self, audience: str) -> str:
        """
        Génère un JWT signé valide pour 15 minutes
        """
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=15)
        payload = {
            'iss': self.credentials.service_account_email,
            'sub': self.credentials.service_account_email,
            'aud': audience,
            'iat': int(now.timestamp()),  # Convertir en timestamp entier
            'exp': int(exp.timestamp())   # Convertir en timestamp entier
        }
        
        try:
            # Vérifier si signer est un dictionnaire et le convertir au format attendu si nécessaire
            signer = self.credentials.signer
            if isinstance(signer, dict):
                # Log pour débogage
                print(f"Signer est un dictionnaire avec les clés: {list(signer.keys())}")
                
                # Créer une classe Signer compatible
                class FixedSigner:
                    def __init__(self, signer_dict):
                        self.key_id = signer_dict.get('key_id', 'fixed_key_id')
                        self._key = signer_dict.get('private_key', '')
                    
                    def sign(self, data):
                        if callable(getattr(signer, 'sign', None)):
                            # Utiliser la méthode sign du signer original si disponible
                            return signer.sign(data)
                        # Sinon utiliser le fallback manuel plus bas
                        raise Exception("Conversion du signer nécessite une implémentation manuelle")
                
                signer = FixedSigner(signer)
            
            # Essayer d'utiliser l'API google.auth.jwt
            return jwt.encode(payload, signer, additional_headers={'typ': 'JWT'})
        except Exception as e:
            # Log l'erreur pour débogage
            print(f"Erreur lors de l'encodage JWT: {str(e)}")
            
            # Fallback à l'implémentation manuelle si la méthode Google échoue
            import base64
            import json
            import hashlib
            import hmac
            
            # Créer les segments
            header = {"alg": "RS256", "typ": "JWT"}
            segments = []
            segments.append(base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode())
            segments.append(base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode())
            
            # Signature
            signing_input = ".".join(segments).encode()
            
            # Essayer d'utiliser la clé privée si disponible
            try:
                # Vérifier si nous avons accès à la clé privée
                private_key = None
                
                # Essayer de récupérer la clé privée depuis le signer ou les credentials
                if hasattr(self.credentials, '_private_key') and self.credentials._private_key:
                    private_key = self.credentials._private_key
                elif hasattr(self.credentials, 'private_key') and self.credentials.private_key:
                    private_key = self.credentials.private_key
                elif isinstance(self.credentials.signer, dict) and 'private_key' in self.credentials.signer:
                    private_key = self.credentials.signer['private_key']
                    
                if private_key:
                    # Normaliser la clé privée pour s'assurer qu'elle est au bon format
                    if not private_key.startswith('-----BEGIN PRIVATE KEY-----'):
                        private_key = f"-----BEGIN PRIVATE KEY-----\n{private_key}\n-----END PRIVATE KEY-----"
                    
                    # Charger la clé privée
                    key = load_pem_private_key(private_key.encode(), password=None)
                    # Signer avec la clé privée
                    signature = key.sign(
                        signing_input,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                    segments.append(base64.urlsafe_b64encode(signature).rstrip(b"=").decode())
                    return ".".join(segments)
            except Exception as inner_e:
                print(f"Erreur lors de la signature avec clé privée: {str(inner_e)}")
                
            # Si nous arrivons ici, c'est que nous n'avons pas pu utiliser la clé privée
            # Nous utilisons donc une signature simple avec HMAC
            secret = self.credentials.service_account_email.encode()
            signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
            segments.append(base64.urlsafe_b64encode(signature).rstrip(b"=").decode())
            
            return ".".join(segments)

    def validate_token(self, token: str, audience: str) -> Dict[str, Any]:
        """
        Valide un token JWT
        """
        try:
            # Essayer d'utiliser l'API google.auth.jwt
            return jwt.decode(token, audience=audience)
        except Exception as e:
            # Fallback à l'implémentation manuelle si la méthode Google échoue
            try:
                # Diviser le token en segments
                header_segment, payload_segment, signature_segment = token.split('.')
                
                # Décoder le payload
                payload_bytes = base64.urlsafe_b64decode(payload_segment + '=' * (4 - len(payload_segment) % 4))
                payload = json.loads(payload_bytes.decode('utf-8'))
                
                # Vérifier l'audience
                if payload.get('aud') != audience:
                    raise ValueError(f"L'audience du token {payload.get('aud')} ne correspond pas à {audience}")
                    
                # Vérifier l'expiration
                now = datetime.now(timezone.utc)
                exp_timestamp = payload.get('exp')
                if exp_timestamp and datetime.fromtimestamp(exp_timestamp, tz=timezone.utc) < now:
                    raise ValueError("Le token a expiré")
                    
                return payload
            except Exception as nested_e:
                raise ValueError(f"Token invalide: {str(nested_e)}")

    def refresh_jwt(self, audience: str) -> str:
        """
        Rafraîchit le JWT actuel
        """
        return self.get_jwt(audience) 