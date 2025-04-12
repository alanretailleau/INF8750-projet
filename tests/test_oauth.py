import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone
import os
import json
from auth.oauth import OAuthManager

# Clé privée mock plus complète et correctement formatée
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

class TestOAuthManager(unittest.TestCase):
    def setUp(self):
        # Mock pour le signer
        self.mock_signer = MagicMock()
        self.mock_signer.key_id = "test_key_id"
        self.mock_signer.sign = MagicMock(return_value=b"signed_data")
        
        # Mock pour les credentials
        self.mock_credentials = MagicMock()
        self.mock_credentials.service_account_email = "test@example.com"
        self.mock_credentials.signer = self.mock_signer
        self.mock_credentials.token = "mock_access_token"
        
        # Mock pour le chargement des credentials
        self.credentials_patcher = patch('google.oauth2.service_account.Credentials.from_service_account_info')
        self.mock_credentials_class = self.credentials_patcher.start()
        self.mock_credentials_class.return_value = self.mock_credentials
        
        # Mock pour l'environnement avec une clé privée valide
        self.mock_credentials_json = {
            "type": "service_account",
            "project_id": "test-project",
            "private_key_id": "mock-key-id-123",
            "private_key": MOCK_PRIVATE_KEY,
            "client_email": "test@example.com"
        }
        self.env_patcher = patch.dict('os.environ', {
            'GOOGLE_APPLICATION_CREDENTIALS': json.dumps(self.mock_credentials_json)
        })
        self.env_patcher.start()
        
        # Mock pour jwt.encode
        self.jwt_encode_patcher = patch('google.auth.jwt.encode')
        self.mock_jwt_encode = self.jwt_encode_patcher.start()
        self.mock_jwt_encode.return_value = "mock_jwt_token"
        
        self.oauth_manager = OAuthManager()

    def tearDown(self):
        self.credentials_patcher.stop()
        self.env_patcher.stop()
        self.jwt_encode_patcher.stop()

    def test_init_loads_credentials(self):
        """Teste que les credentials sont chargés à l'initialisation"""
        self.mock_credentials_class.assert_called_once_with(
            self.mock_credentials_json,
            scopes=[
                'https://www.googleapis.com/auth/cloud-platform',
                'https://www.googleapis.com/auth/userinfo.email'
            ]
        )
        self.assertEqual(self.oauth_manager.credentials, self.mock_credentials)

    def test_get_jwt_creates_valid_token(self):
        """Teste la création d'un JWT valide"""
        audience = "https://example.com"
        token = self.oauth_manager.get_jwt(audience)
        
        # Vérifie que jwt.encode a été appelé avec les bons arguments
        self.mock_jwt_encode.assert_called_once()
        args, kwargs = self.mock_jwt_encode.call_args
        
        # Vérifie les arguments
        payload, signer = args
        self.assertEqual(payload['aud'], audience)
        self.assertEqual(payload['iss'], "test@example.com")
        self.assertEqual(signer, self.mock_signer)
        
        # Vérifie les kwargs
        self.assertIn('additional_headers', kwargs)
        self.assertEqual(kwargs['additional_headers'], {'typ': 'JWT'})
        
        # Vérifie le token retourné
        self.assertEqual(token, "mock_jwt_token")

    def test_refresh_jwt_creates_new_token(self):
        """Teste que refresh_jwt crée un nouveau token"""
        audience = "https://example.com"
        
        # Configure jwt.encode pour retourner des tokens différents
        self.mock_jwt_encode.side_effect = ["token1", "token2"]
        
        token1 = self.oauth_manager.get_jwt(audience)
        token2 = self.oauth_manager.refresh_jwt(audience)
        
        # Les tokens devraient être différents
        self.assertNotEqual(token1, token2)
        self.assertEqual(token1, "token1")
        self.assertEqual(token2, "token2")

    def test_missing_credentials_raises_error(self):
        """Teste que l'absence de credentials lève une erreur"""
        with patch.dict('os.environ', {}, clear=True):
            with self.assertRaises(ValueError):
                OAuthManager()

    def test_get_access_token_returns_cached_token(self):
        """Teste que get_access_token retourne le token en cache s'il est valide"""
        # Configure un token en cache valide
        self.oauth_manager._access_token = "cached_token"
        self.oauth_manager._token_expiry = datetime.now(timezone.utc) + timedelta(minutes=30)
        
        token = self.oauth_manager.get_access_token()
        self.assertEqual(token, "cached_token")
        self.mock_credentials.refresh.assert_not_called()

    def test_get_access_token_refreshes_expired_token(self):
        """Teste que get_access_token rafraîchit le token expiré"""
        # Configure un token en cache expiré
        self.oauth_manager._access_token = "expired_token"
        self.oauth_manager._token_expiry = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        token = self.oauth_manager.get_access_token()
        self.assertEqual(token, "mock_access_token")
        self.mock_credentials.refresh.assert_called_once()

    def test_validate_token_success(self):
        """Teste la validation réussie d'un token"""
        audience = "https://example.com"
        mock_payload = {"sub": "test@example.com", "aud": audience}
        
        with patch('google.auth.jwt.decode', return_value=mock_payload):
            result = self.oauth_manager.validate_token("valid_token", audience)
            self.assertEqual(result, mock_payload)

    def test_validate_token_failure(self):
        """Teste la validation échouée d'un token"""
        audience = "https://example.com"
        
        with patch('google.auth.jwt.decode', side_effect=Exception("Invalid token")):
            with self.assertRaises(ValueError) as context:
                self.oauth_manager.validate_token("invalid_token", audience)
            self.assertIn("Token invalide", str(context.exception))

if __name__ == '__main__':
    unittest.main() 