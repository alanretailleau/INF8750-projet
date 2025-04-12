import logging
import os
from datetime import datetime

def setup_logger(name: str) -> logging.Logger:
    """
    Configure un logger avec rotation des fichiers
    """
    # Création du répertoire logs s'il n'existe pas
    os.makedirs('logs', exist_ok=True)
    
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Format des logs
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Handler pour la console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Handler pour le fichier
    file_handler = logging.FileHandler(
        f'logs/{name}_{datetime.now().strftime("%Y%m%d")}.log'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger 