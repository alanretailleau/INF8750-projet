# 🛡️ Politique de sécurité

## 🔐 Gestion des identifiants

- Les identifiants de service GCP sont stockés dans un fichier JSON séparé
- Le fichier d'identifiants n'est jamais commité dans le dépôt
- Les identifiants sont chargés via les variables d'environnement

## ⏱️ Durée de validité

- JWT : 15 minutes
- Certificats X.509 : 24 heures
- Renouvellement automatique des certificats avant expiration

## 📦 Stockage des certificats

- Les certificats sont stockés localement dans le répertoire `.certs/`
- Le répertoire `.certs/` est ajouté au `.gitignore`
- Les permissions du répertoire sont restreintes
- Les certificats sont chiffrés au repos

## 🔄 Révocation

- Les certificats peuvent être révoqués via l'API GCP IAM
- La révocation est immédiate et propagée
- Les certificats révoqués sont automatiquement renouvelés

## 🚨 Bonnes pratiques

- Ne jamais stocker de secrets dans le code
- Utiliser des variables d'environnement pour la configuration
- Maintenir les dépendances à jour
- Effectuer des audits de sécurité réguliers
- Documenter les incidents de sécurité

## 📝 Reporting des vulnérabilités

En cas de découverte d'une vulnérabilité, merci de :
1. Ne pas divulguer publiquement la vulnérabilité
2. Contacter l'équipe de sécurité via [email protégé]
3. Fournir une description détaillée du problème
4. Attendre la confirmation de la correction avant de divulguer 