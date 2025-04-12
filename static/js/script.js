/**
 * Script principal pour l'application d'authentification
 */

// Fonction exécutée lorsque le document est chargé
document.addEventListener('DOMContentLoaded', function() {
    console.log('Application d\'authentification initialisée');
    
    // Vérifier si nous sommes de retour d'un callback OAuth (présence de code et state dans l'URL)
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    
    if (code && state) {
        showMessage('Authentification en cours...', 'info');
    }
    
    // Ajouter des gestionnaires d'événements pour les boutons
    setupEventListeners();
});

/**
 * Configure les écouteurs d'événements
 */
function setupEventListeners() {
    // Bouton pour copier le JWT dans le presse-papier
    const copyButtons = document.querySelectorAll('.btn-copy');
    if (copyButtons) {
        copyButtons.forEach(button => {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                const textToCopy = this.dataset.copy;
                if (textToCopy) {
                    copyToClipboard(textToCopy);
                    showMessage('Copié dans le presse-papier !', 'success');
                }
            });
        });
    }
}

/**
 * Copie un texte dans le presse-papier
 */
function copyToClipboard(text) {
    // Méthode moderne pour copier dans le presse-papier
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text)
            .catch(err => {
                console.error('Erreur lors de la copie :', err);
            });
    } else {
        // Fallback pour les navigateurs plus anciens
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';  // Pour éviter de perturber la mise en page
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
        } catch (err) {
            console.error('Erreur lors de la copie :', err);
        }
        document.body.removeChild(textarea);
    }
}

/**
 * Affiche un message temporaire à l'utilisateur
 */
function showMessage(message, type = 'info') {
    // Créer l'élément de toast
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    // Ajouter au DOM
    const toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.style.position = 'fixed';
        container.style.bottom = '20px';
        container.style.right = '20px';
        container.style.zIndex = '1000';
        document.body.appendChild(container);
    }
    
    document.getElementById('toast-container').appendChild(toast);
    
    // Animation d'entrée
    setTimeout(() => {
        toast.style.opacity = '1';
    }, 10);
    
    // Supprimer après 3 secondes
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 3000);
} 