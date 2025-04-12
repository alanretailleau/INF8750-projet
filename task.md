# Projet d'Authentification Hybride avec GCP

## ✅ Tâches Complétées

### Configuration Initiale
- [x] Création de la structure du projet
- [x] Configuration du fichier `requirements.txt` avec les dépendances nécessaires
- [x] Mise en place du fichier `.env` pour les variables d'environnement
- [x] Création du `Dockerfile` pour le conteneur
- [x] Création du script de déploiement `deploy.sh`

### Configuration GCP
- [x] Configuration du projet GCP (`inf8750-456601`)
- [x] Activation des APIs nécessaires (Cloud Run, Cloud Build, Private CA)
- [x] Création du CA Pool dans la région `northamerica-northeast1`
- [x] Création et activation de l'autorité de certification racine `auth-ca` dans le pool
- [x] Création et configuration du compte de service avec les permissions nécessaires
- [x] Génération des credentials du compte de service

### Déploiement et Configuration
- [x] Build et push de l'image Docker vers Google Container Registry
- [x] Configuration des variables d'environnement sur Cloud Run
- [x] Correction des importations pour Google Cloud Private CA
- [x] Test réussi de l'application en local
- [x] Déploiement réussi sur Cloud Run
- [x] Service accessible via URL publique : https://auth-hybrid-352667335817.northamerica-northeast1.run.app

### Gestion des Certificats X.509
- [x] Implémenter la classe `PKIManager` pour la gestion des certificats
- [x] Configurer l'interaction avec Google Cloud Certificate Authority
- [x] Mettre en place le stockage sécurisé des certificats dans `.certs/`
- [x] Implémenter la validation des certificats
- [x] Implémenter les tests unitaires pour la gestion des certificats
- [x] Ajouter la fonctionnalité de sauvegarde et chargement des certificats

### Authentification OAuth 2.0
- [x] Implémenter la classe `OAuthManager` pour la gestion des tokens
- [x] Implémenter la génération du JWT signé avec une expiration de 15 minutes
- [x] Implémenter la validation des tokens JWT
- [x] Implémenter la gestion du cache des tokens d'accès
- [x] Écrire les tests unitaires pour la gestion OAuth
- [x] Implémenter l'endpoint `/auth/init` pour démarrer le flux OAuth
- [x] Implémenter l'endpoint `/auth/callback` pour gérer le retour OAuth
- [x] Implémenter la gestion sécurisée des états OAuth avec expiration
- [x] Écrire les tests unitaires pour les endpoints d'authentification

### Interface Utilisateur
- [x] Création d'une interface web pour l'authentification
- [x] Ajout d'une page d'accueil avec bouton de connexion
- [x] Ajout d'une page de résultat pour afficher le JWT et le certificat
- [x] Ajout d'une page pour visualiser les requêtes authentifiées
- [x] Implémentation des styles CSS et scripts JS pour l'UI

### Signature des Requêtes
- [x] Implémenter le middleware de signature des requêtes sortantes
- [x] Ajouter une méthode pour effectuer des requêtes signées automatiquement
- [x] Implémenter un décorateur pour protéger les routes avec authentification

## 🚧 Problèmes Résolus
- [x] Correction de l'importation du module Private CA (de `google.cloud.private_ca_v1` à `google.cloud.security.privateca_v1`)
- [x] Validation des importations en environnement local
- [x] Application fonctionnelle en local avec les nouvelles importations
- [x] Déploiement réussi sur Cloud Run
- [x] Correction des avertissements de dépréciation de `datetime.utcnow()`
- [x] Mise à jour des tests pour utiliser les bonnes importations et les bonnes méthodes de datetime
- [x] Correction du format de la clé publique (PEM au lieu de DER)
- [x] Implémentation de l'injection de dépendances pour faciliter les tests
- [x] Mock correct du client Private CA pour les tests unitaires
- [x] Correction des mocks pour le JWT signer dans les tests OAuth
- [x] Ajout des dépendances manquantes pour OAuth 2.0
- [x] Résolution du problème `'dict' object has no attribute 'key_id'` lors de la génération JWT en production
- [x] Implémentation d'une solution de fallback robuste pour la signature JWT
- [x] Création et activation d'une autorité de certification racine dans le CA Pool
- [x] Optimisation du script de déploiement pour gérer les sessions persistantes
- [x] Implémentation de l'affinité de session sur Cloud Run

## 📝 Tâches Restantes

### Déploiement
- [x] Déploiement de la nouvelle version sur Cloud Run avec les corrections des clés privées
- [x] Validation du service en production

### Authentification OAuth 2.0
- [x] Configurer les credentials OAuth dans GCP
- [x] Tester le flux d'authentification en production

### Gestion des Certificats X.509
- [x] Implémenter l'endpoint de demande de certificat X.509
- [ ] Implémenter le renouvellement automatique des certificats
- [ ] Configurer la révocation des certificats via IAM

### Signature des Requêtes
- [x] Implémenter le middleware de signature des requêtes sortantes
- [ ] Mettre en place la rotation automatique des certificats expirés

### Tests et Documentation
- [x] Écrire les tests unitaires pour la gestion des certificats
- [x] Écrire les tests unitaires pour la gestion OAuth
- [x] Écrire les tests unitaires pour les endpoints d'authentification
- [ ] Écrire les tests d'intégration pour les flux complets
- [ ] Documenter l'API (Swagger/OpenAPI)
- [ ] Créer un guide d'utilisation détaillé
- [ ] Documenter les procédures de sécurité et de maintenance

### Monitoring et Logging
- [x] Configurer le logging des opérations critiques
- [ ] Mettre en place le monitoring des certificats
- [ ] Configurer les alertes pour les événements importants
- [ ] Implémenter des métriques de performance

## 🔒 Considérations de Sécurité
- Tous les certificats sont stockés de manière sécurisée dans le répertoire `.certs/`
- Les clés privées ne quittent jamais le conteneur
- Les permissions IAM suivent le principe du moindre privilège
- Les logs ne doivent pas contenir d'informations sensibles
- La rotation régulière des certificats doit être automatisée
- Les certificats sont validés avant utilisation
- L'injection de dépendances facilite les tests et améliore la sécurité
- Les tokens JWT ont une durée de vie limitée (15 minutes)
- Les tokens d'accès sont mis en cache de manière sécurisée
- Les états OAuth sont nettoyés automatiquement après expiration
- Les callbacks OAuth sont validés avec un état unique et temporaire
- Fallback sécurisé pour la génération JWT en cas d'échec de la méthode principale
- Sessions persistantes avec clé secrète sécurisée pour Cloud Run
- L'affinité de session est activée pour maintenir les sessions utilisateur

## 🔄 Prochaines Étapes
1. ✅ Valider le flux d'authentification JWT en production
2. ✅ Tester le flux OAuth complet en production
3. ✅ Développer l'interface utilisateur conviviale
4. ✅ Implémenter la signature automatique des requêtes
5. 🔄 Mettre en place le renouvellement automatique des certificats
6. 🔄 Implémenter la rotation des certificats expirés
7. 🔄 Déployer la documentation complète de l'API 