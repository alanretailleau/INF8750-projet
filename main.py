from flask import Flask, jsonify, request, redirect, session, make_response, render_template
from auth.oauth import OAuthManager
from auth.pki import PKIManager
from auth.signer import RequestSigner
import os
from dotenv import load_dotenv
import json
from flask_cors import CORS
from functools import wraps
import secrets
from flask_session import Session  # Pour gérer les sessions persistantes

# Chargement des variables d'environnement
load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')
# Utilisation d'une clé secrète persistante définie dans l'environnement, ou génération d'une aléatoire en local
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(16))

# Configuration de la session Flask
# Par défaut, utilisez le système de fichiers pour le développement local
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './.flask_session'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 heures en secondes

# Si une URL Redis est fournie, utilisez Redis comme backend de session
redis_url = os.getenv('REDIS_URL')
if redis_url:
    import redis
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis.from_url(redis_url)

# Initialisation de l'extension de session
Session(app)

CORS(app)  # Activation de CORS pour permettre les requêtes cross-origin

# Initialisation des managers
oauth_manager = OAuthManager()
pki_manager = PKIManager()
request_signer = RequestSigner()

# Fonction de décorateur pour vérifier la présence et validité du certificat
def requires_certificate(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Vérifier si un certificat est stocké en session
        cert_data = session.get('certificate')
        jwt_token = session.get('jwt')
        
        if not cert_data or not jwt_token:
            # Rediriger vers l'authentification si aucun certificat n'est présent
            return redirect('/auth/init')
        
        # Ajouter le certificat et le JWT aux arguments du contexte de requête
        request.cert_data = cert_data
        request.jwt_token = jwt_token
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    """
    Page d'accueil
    """
    return render_template('index.html')

@app.route('/auth/init', methods=['GET'])
def init_auth():
    """
    Initialise le flux d'authentification OAuth et redirige directement vers Google
    """
    try:
        auth_data = oauth_manager.init_oauth_flow()
        # Stocke l'état dans la session pour le récupérer lors du callback
        session['oauth_state'] = auth_data['state']
        # Redirige directement vers l'URL d'authentification Google
        return redirect(auth_data['auth_url'])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/callback', methods=['GET'])
def auth_callback():
    """
    Gère le callback OAuth et génère les credentials
    """
    try:
        # Récupère les paramètres
        code = request.args.get('code')
        state = request.args.get('state')
        
        if not code or not state:
            return jsonify({'error': 'Missing required parameters'}), 400
            
        try:
            # Valide le callback et obtient le token
            token_data = oauth_manager.validate_oauth_callback(code, state)
            
            # Génère un JWT
            jwt_token = oauth_manager.get_jwt(request.host_url)
            
            # Demande un certificat
            certificate = pki_manager.request_certificate(token_data['access_token'])
            
            # Extraire les informations pertinentes du certificat pour la réponse JSON
            cert_info = {
                'pem_certificate': certificate.pem_certificate if hasattr(certificate, 'pem_certificate') else None,
                'name': certificate.name if hasattr(certificate, 'name') else None,
                'create_time': str(certificate.create_time) if hasattr(certificate, 'create_time') else None,
                'update_time': str(certificate.update_time) if hasattr(certificate, 'update_time') else None,
                'expire_time': str(certificate.expire_time) if hasattr(certificate, 'expire_time') else None
            }
            
            # Stocker le certificat et le JWT en session
            session['certificate'] = cert_info
            session['jwt'] = jwt_token
            session['expires_in'] = token_data['expires_in']
            
            # Enregistrer le certificat localement pour les futures requêtes
            if cert_info['pem_certificate']:
                pki_manager.save_certificate(cert_info['pem_certificate'])
            
            # Format de réponse basé sur le header Accept
            accept_header = request.headers.get('Accept', '')
            
            # Si le client attend du JSON, retourner le format JSON
            if 'application/json' in accept_header:
                return jsonify({
                    'jwt': jwt_token,
                    'certificate': cert_info,
                    'expires_in': token_data['expires_in'],
                    'message': 'Authentification réussie et certificat stocké'
                })
            # Sinon rendre la page HTML
            else:
                return render_template('callback_success.html', 
                                      jwt=jwt_token, 
                                      certificate=cert_info, 
                                      expires_in=token_data['expires_in'])
            
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/hello', methods=['GET'])
@requires_certificate
def hello():
    """
    Endpoint de test protégé par signature X.509
    """
    return jsonify({"message": "Hello, World! Authentifié avec certificat."})

@app.route('/auth/cert-auth', methods=['GET'])
def cert_auth_request():
    """
    Effectue une requête automatiquement authentifiée avec le certificat stocké
    """
    # Récupérer les informations du certificat et JWT depuis la session
    cert_data = session.get('certificate')
    jwt_token = session.get('jwt')
    
    if not cert_data or not jwt_token:
        return redirect('/auth/init')
    
    # URL cible (dans cet exemple, nous appelons notre propre endpoint /hello)
    target_url = request.args.get('url', request.host_url + 'hello')
    
    try:
        # Vérifier que le certificat est bien enregistré localement
        if not os.path.exists(pki_manager.get_certificate_path()):
            # Si le certificat n'est pas enregistré localement, l'enregistrer
            pki_manager.save_certificate(cert_data['pem_certificate'])
        
        # Effectuer la requête signée
        response = request_signer.make_signed_request(
            method='GET', 
            url=target_url,
            jwt_token=jwt_token
        )
        
        # Format de réponse basé sur le header Accept
        accept_header = request.headers.get('Accept', '')
        
        # Si le client attend du JSON, retourner le format JSON
        if 'application/json' in accept_header:
            return jsonify({
                'success': True,
                'status_code': response.status_code,
                'response': response.text,
                'message': 'Requête authentifiée effectuée avec succès'
            })
        # Sinon rendre la page HTML
        else:
            # Récupérer les headers utilisés pour la requête
            headers = response.request.headers
            
            return render_template('auth_request.html',
                                  target_url=target_url,
                                  headers=dict(headers),
                                  status_code=response.status_code,
                                  response=response.text)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/status', methods=['GET'])
def status():
    """
    Vérifie le statut de l'authentification
    """
    cert_data = session.get('certificate')
    jwt_token = session.get('jwt')
    
    if cert_data and jwt_token:
        return jsonify({
            'authenticated': True,
            'certificate_present': True,
            'jwt_present': True,
            'expires_in': session.get('expires_in', 'unknown')
        })
    else:
        return jsonify({
            'authenticated': False,
            'certificate_present': cert_data is not None,
            'jwt_present': jwt_token is not None
        })

if __name__ == '__main__':
    # Création du répertoire .certs s'il n'existe pas
    os.makedirs('.certs', exist_ok=True)
    
    # Afficher les informations importantes au démarrage
    print(f"\n{'='*80}")
    print(f"Démarrage du service d'authentification hybride")
    print(f"{'='*80}")
    print(f"URL de redirection OAuth configurée: {os.getenv('OAUTH_REDIRECT_URI', 'Non définie')}")
    print(f"URL de pool CA: {os.getenv('CA_POOL_PATH', 'Non défini')}")
    
    is_local = os.getenv('K_SERVICE') is None
    if is_local:
        print(f"\n⚠️  MODE LOCAL DÉTECTÉ ⚠️")
        print(f"L'authentification OAuth ne fonctionnera pas correctement sans URL de redirection publique.")
        print(f"Pensez à déployer sur GCP avec le script deploy.sh pour un fonctionnement complet.")
    
    # Démarrage de l'application
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=is_local) 