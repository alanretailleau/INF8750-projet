from auth.oauth import OAuthManager
import json
import os
from unittest.mock import patch, MagicMock
import pytest

# Classe pour simuler le Signer
class MockSigner:
    def __init__(self):
        self.key_id = "mock-key-id"
    
    def sign(self, data):
        return b"mock-signature"

# Clé privée mock pour les tests
MOCK_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfxCDCpiqU8Grl
7Gqy5qf5XhZpPZALqjxI8d4jQgdN8fdNo/gxjr/2KTpvE+pcPgxuXzEsCwRmHN2y
Lk9AXv+cN1jcWeiT+rDP+itCnzcxU09AbLBqL+iHjxqQcR8+5q3AzEP5NW73EDmC
fI9HNAYlT50n2BKtAI4YZgklFHLFPwcHXRJ9HgTRYVQFiQ3tgJ1YSV02eb0z4KCQ
4POdkGPBzqB+mUTohcyA9T4H2l5LYEg4Ku5GQRh6gqCFNQfKrMAHjD2Ee3eXCLM0
ZFLMnKdQCDsTGP9E2y3vSVbvlOOJ16NAkuRwMBCqLWBpaZUg2UxTFGGEVINSAgkL
uoBJb6bZAgMBAAECggEADWZPJr9ubtYWPsBvbzx0qseHEFMm3mYIQCBm7sXJX7cg
1k3vrfP2CwVc7BEZP6B39aB3vKGzu9vFG3EJmXiOGVo7KT7m5L5LWhFzjkKeF0+o
TIJCeUDGX5+6i4IQ4hsXYsG8dKrOO5JjTmjKPIH4wFgT6+jVj5XB3+BXbe8N8qnx
ubZ9YjPIoa8COuZSiULcnWQPJUaDyDsYEGZxLYYfyZ+L9ah5p5AJH0Z2ADGQSDlY
OXs2GPypA3REcyBnPjwInP4rl2JZ0fFRwCbmbFTDZ9WU9PbCFe1AJRHpHWvFnH8A
9iW4ybMLkhwkKxGoye+6l3BizvJLi7CdkJqLKQdbKQKBgQDRNP2Wc3wZ/nXseaLP
OwEXeBDAkGQiDvn1Xi5SbIIjhJhKGQNAh6+wHtHOqXBKlHGQYQTfQHQNR9ep3bgR
2jfYFCHMnRKL1nOE8y0Q2wFyVS1BoBpLUg5ufv2dxIQYLJQIWbOM+KbCOTZ4hAoH
0Twk5NRZcPYQQXQXs/MkUYNa3wKBgQDDMPKuT1ReBJgvO8gW0XuQYNCiTAjpAMZH
WDuJYtFGzD0Tj2ADkUbTVTYZYkV0PspYZxJ6Td3CYWBIKmxQZhBdMXhLQ2UZdSbM
e8g3YNX4MjP7SgVJzEgftJYCiMIieokGje6QTPqcTB8+PPIBGhsWKV1ybN1dFu35
1x8iLJRpFwKBgC9Ue614mw7kAhiPHdWj35EE0y1+uNhOWtLLUDcxgd7qKjVLvZeu
iVPJQPjLdg86f7/TYE3p/hKw7xJ1qcXeJkSbfVhxUJO1poHgg2xAUNdQDKjztYoA
pI14McYh2G53kZ5l/P1PNUywQImhwE6xtf0FS0Wo4YA+Lin0SYtFXzLDAoGAV+Gq
XjR/P9RT6zzITUh1RxQMnVFz26OYc7O5MaB1Znw0dwsRKQzQ0UIuuGkJJzAfCzVt
d5AxoPrPT8So3NUvqXbG2GPRZb0xSTqC32tR6XjlUPGzmAM9fdKCEVJiRZipDOQK
pBzogwxQ+/HOBJDsGfXgZMN0FvKXrv0GgwKg/u0CgYEAqX6N7zRK7MHs+QXgS+Ji
Q2EIfTRnT4KcDH0N34XX9iRrCRX2fYHKY5hfALJLVS31fBg+HeOdmBnFSoJGCw0r
dwBvauRloqvoaIHnwHwbAGGponYIkqsQFCrHn5XVzNnV1lcTndO+VYawkvAkqBQZ
TYLh6WyobtDQQrHYEd3VQIk=
-----END PRIVATE KEY-----
"""

def test_jwt_generation():
    """Test fonctionnel pour la génération d'un JWT"""
    
    # Clean les variables d'environnement précédentes
    if 'GOOGLE_APPLICATION_CREDENTIALS' in os.environ:
        del os.environ['GOOGLE_APPLICATION_CREDENTIALS']
    
    # Créer un mock pour l'objet credentials
    mock_credentials = MagicMock()
    mock_credentials.service_account_email = "test@example.com"
    mock_credentials.signer = MockSigner()
    
    # Patch la méthode _load_credentials pour éviter de charger les vraies credentials
    with patch.object(OAuthManager, '_load_credentials') as mock_load:
        with patch('google.auth.jwt.encode', return_value='mocked-jwt-token') as mock_encode:
            # Configurer le manager pour utiliser notre mock
            manager = OAuthManager()
            manager.credentials = mock_credentials
            
            # Tester la génération du JWT
            audience = "https://test-audience.com"
            token = manager.get_jwt(audience)
            
            # Vérifications
            assert token == 'mocked-jwt-token'
            mock_encode.assert_called_once()
            # Vérifier que les bons arguments sont passés à jwt.encode
            args, kwargs = mock_encode.call_args
            payload, signer = args
            assert payload['aud'] == audience
            assert payload['iss'] == "test@example.com"
            assert signer is mock_credentials.signer
            
            print(f"JWT généré avec succès avec un signer objet: {token}")

def test_jwt_generation_with_dict_signer():
    """Test fonctionnel pour la génération d'un JWT avec un signer dictionnaire"""
    
    # Clean les variables d'environnement précédentes
    if 'GOOGLE_APPLICATION_CREDENTIALS' in os.environ:
        del os.environ['GOOGLE_APPLICATION_CREDENTIALS']
    
    # Créer un mock pour l'objet credentials avec un signer dictionnaire
    mock_credentials = MagicMock()
    mock_credentials.service_account_email = "test@example.com"
    mock_credentials.signer = {
        'key_id': 'dict-key-id',
        'private_key': MOCK_PRIVATE_KEY
    }
    
    # Patch la méthode _load_credentials pour éviter de charger les vraies credentials
    with patch.object(OAuthManager, '_load_credentials'):
        # Configurer le manager pour utiliser notre mock
        manager = OAuthManager()
        manager.credentials = mock_credentials
        
        # Tester la génération du JWT
        audience = "https://test-audience.com"
        token = manager.get_jwt(audience)
        
        # Vérifications de base (nous ne pouvons pas vérifier les détails de l'implémentation)
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
        assert "." in token  # Un JWT a au moins un point
        
        print(f"JWT généré avec succès avec un signer dictionnaire: {token}")

if __name__ == "__main__":
    try:
        test_jwt_generation()
        test_jwt_generation_with_dict_signer()
        print("Tous les tests ont réussi!")
    except Exception as e:
        print(f"Erreur pendant le test: {e}") 