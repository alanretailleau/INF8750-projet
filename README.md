# 🔐 Authentification hybride avec Google Cloud Platform

Ce projet implémente une solution d'authentification hybride utilisant OAuth 2.0 et des certificats X.509 pour sécuriser les communications entre services.

## 🚀 Fonctionnalités

- Authentification OAuth 2.0 avec GCP
- Génération de JWT signés (15 minutes de validité)
- Obtention de certificats X.509 via Google Cloud CA
- Signature automatique des requêtes sortantes
- Stockage sécurisé des certificats
- Renouvellement automatique des certificats

## 📋 Prérequis

- Un projet GCP actif
- Un CA Pool configuré dans GCP
- Des identifiants de service GCP valides
- Python 3.8+

## 🔧 Configuration

1. Créez un fichier `.env` à la racine du projet avec les variables suivantes :
```env
GOOGLE_APPLICATION_CREDENTIALS=chemin/vers/votre/credentials.json
CA_POOL_PATH=projects/votre-projet/locations/global/caPools/votre-pool
```

2. Installez les dépendances :
```bash
pip install -r requirements.txt
```

## 🏃‍♂️ Déploiement sur Cloud Run

1. Construisez l'image Docker :
```bash
gcloud builds submit --tag gcr.io/votre-projet/auth-hybrid
```

2. Déployez sur Cloud Run :
```bash
gcloud run deploy auth-hybrid \
  --image gcr.io/votre-projet/auth-hybrid \
  --platform managed \
  --region us-central1
```

## 🔐 Exemple d'utilisation

```python
import requests
from auth.signer import RequestSigner

signer = RequestSigner()
headers = signer.sign_request(
    method='GET',
    url='https://api.example.com/endpoint',
    data='{"key": "value"}'
)

response = requests.get(
    'https://api.example.com/endpoint',
    headers=headers,
    data='{"key": "value"}'
)
```

## 🔄 Renouvellement automatique

Le système vérifie automatiquement la validité des certificats et les renouvelle si nécessaire. Les certificats sont valides pendant 24 heures.

## 🛡️ Sécurité

- Les JWT expirent après 15 minutes
- Les certificats sont valides 24 heures
- Stockage local sécurisé des certificats
- Possibilité de révocation via IAM
- Aucun secret stocké en dur dans le code 