#!/bin/bash

# Configuration du projet GCP
PROJECT_ID="inf8750-456601"
REGION="northamerica-northeast1"
SERVICE_NAME="auth-hybrid"
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"
SERVICE_URL="https://auth-hybrid-352667335817.northamerica-northeast1.run.app"
REDIS_INSTANCE_NAME="auth-session-store"
VPC_CONNECTOR="auth-serverless-connector"

# Génération d'une clé secrète pour les sessions Flask (peut être remplacée par une clé fixe)
FLASK_SECRET_KEY=$(openssl rand -base64 32)

# Vérifier si l'instance Redis existe déjà
REDIS_INSTANCE=$(gcloud redis instances list --region=${REGION} --filter="name~${REDIS_INSTANCE_NAME}" --format="value(name)" || echo "")

# Si l'instance Redis n'existe pas, la créer
if [ -z "$REDIS_INSTANCE" ]; then
    echo "🚀 Création de l'instance Redis Memorystore..."
    
    # Vérifier si le connecteur VPC Serverless existe
    VPC_EXISTS=$(gcloud compute networks vpc-access connectors list --region=${REGION} --filter="name~${VPC_CONNECTOR}" --format="value(name)" || echo "")
    
    # Si le connecteur VPC n'existe pas, le créer
    if [ -z "$VPC_EXISTS" ]; then
        echo "🚀 Création du connecteur VPC Serverless..."
        gcloud compute networks vpc-access connectors create ${VPC_CONNECTOR} \
            --region=${REGION} \
            --network=default \
            --range=10.8.0.0/28
    fi
    
    # Créer l'instance Redis
    gcloud redis instances create ${REDIS_INSTANCE_NAME} \
        --size=1 \
        --region=${REGION} \
        --tier=basic \
        --redis-version=redis_6_x
    
    # Attendre que l'instance soit prête
    echo "⏳ Attente de la création de l'instance Redis..."
    sleep 60
fi

# Récupérer l'adresse IP de l'instance Redis
REDIS_HOST=$(gcloud redis instances describe ${REDIS_INSTANCE_NAME} --region=${REGION} --format="value(host)")
REDIS_PORT=$(gcloud redis instances describe ${REDIS_INSTANCE_NAME} --region=${REGION} --format="value(port)")
REDIS_URL="redis://${REDIS_HOST}:${REDIS_PORT}"

# Construction de l'image Docker
echo "🚀 Construction de l'image Docker..."
gcloud builds submit --tag ${IMAGE_NAME}

# Déploiement sur Cloud Run
echo "🚀 Déploiement sur Cloud Run..."
gcloud run deploy ${SERVICE_NAME} \
  --image ${IMAGE_NAME} \
  --platform managed \
  --region ${REGION} \
  --allow-unauthenticated \
  --set-env-vars="CA_POOL_PATH=projects/${PROJECT_ID}/locations/${REGION}/caPools/auth-pool,GOOGLE_OAUTH_CLIENT_ID=${GOOGLE_OAUTH_CLIENT_ID},GOOGLE_OAUTH_CLIENT_SECRET=${GOOGLE_OAUTH_CLIENT_SECRET},OAUTH_REDIRECT_URI=${SERVICE_URL}/auth/callback,FLASK_SECRET_KEY=${FLASK_SECRET_KEY},REDIS_URL=${REDIS_URL}" \
  --set-secrets="GOOGLE_APPLICATION_CREDENTIALS=credentials:latest" \
  --vpc-connector=${VPC_CONNECTOR} \
  --min-instances=1 \
  --session-affinity \
  --memory=512Mi

echo "✅ Déploiement terminé !"
echo "📝 URL du service : ${SERVICE_URL}" 