import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import json
import os
from main import app

class TestAuthRoutes(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        
        # Mock pour OAuthManager
        self.mock_oauth_manager = MagicMock()
        self.oauth_patcher = patch('main.oauth_manager', self.mock_oauth_manager)
        self.oauth_patcher.start()
        
        # Mock pour PKIManager
        self.mock_pki_manager = MagicMock()
        self.pki_patcher = patch('main.pki_manager', self.mock_pki_manager)
        self.pki_patcher.start()

    def tearDown(self):
        self.oauth_patcher.stop()
        self.pki_patcher.stop()

    def test_oauth_init_success(self):
        """Teste l'initialisation réussie du flux OAuth"""
        # Configure le mock
        expected_response = {
            'auth_url': 'https://accounts.google.com/o/oauth2/auth',
            'state': 'random_state_token'
        }
        self.mock_oauth_manager.init_oauth_flow.return_value = expected_response

        # Fait la requête
        response = self.app.get('/auth/init')
        data = json.loads(response.data)

        # Vérifie la réponse
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data, expected_response)
        self.mock_oauth_manager.init_oauth_flow.assert_called_once()

    def test_oauth_callback_success(self):
        """Teste le callback OAuth réussi"""
        # Configure les mocks
        self.mock_oauth_manager.validate_oauth_callback.return_value = {
            'access_token': 'valid_token',
            'expires_in': 3600
        }
        self.mock_oauth_manager.get_jwt.return_value = 'valid_jwt'
        self.mock_pki_manager.request_certificate.return_value = 'cert_data'

        # Fait la requête
        response = self.app.get('/auth/callback?code=test_code&state=test_state')
        data = json.loads(response.data)

        # Vérifie la réponse
        self.assertEqual(response.status_code, 200)
        self.assertIn('jwt', data)
        self.assertIn('certificate', data)
        self.mock_oauth_manager.validate_oauth_callback.assert_called_once_with('test_code', 'test_state')
        self.mock_pki_manager.request_certificate.assert_called_once()

    def test_oauth_callback_invalid_state(self):
        """Teste le callback OAuth avec un state invalide"""
        # Configure le mock pour lever une exception
        self.mock_oauth_manager.validate_oauth_callback.side_effect = ValueError("Invalid state")

        # Fait la requête
        response = self.app.get('/auth/callback?code=test_code&state=invalid_state')
        data = json.loads(response.data)

        # Vérifie la réponse
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Invalid state')

    def test_oauth_callback_missing_params(self):
        """Teste le callback OAuth avec des paramètres manquants"""
        # Fait la requête sans paramètres
        response = self.app.get('/auth/callback')
        data = json.loads(response.data)

        # Vérifie la réponse
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Missing required parameters')

    def test_oauth_callback_server_error(self):
        """Teste le callback OAuth avec une erreur serveur"""
        # Configure le mock pour lever une exception
        self.mock_oauth_manager.validate_oauth_callback.side_effect = Exception("Server error")

        # Fait la requête
        response = self.app.get('/auth/callback?code=test_code&state=test_state')
        data = json.loads(response.data)

        # Vérifie la réponse
        self.assertEqual(response.status_code, 500)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Server error')

if __name__ == '__main__':
    unittest.main() 