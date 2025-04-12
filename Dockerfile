FROM python:3.9-slim

WORKDIR /app

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copie des fichiers de dépendances
COPY requirements.txt .

# Installation des dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code source
COPY . .

# Création des répertoires nécessaires
RUN mkdir -p .certs logs .flask_session

# Configuration des permissions
RUN chmod 700 .certs
RUN chmod 700 .flask_session

# Exposition du port
EXPOSE 8080

# Commande de démarrage
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "main:app"] 