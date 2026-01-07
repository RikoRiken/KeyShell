# --- Lecture, Ecriture, Suppression de fichiers dans le coffre --- 
import os

DOSSIER_DATA = "passwords"

# Initialise le dossier de stockage des fichiers s'il n'existe pas
def init_dossier():
    if not os.path.exists(DOSSIER_DATA):
        os.makedirs(DOSSIER_DATA)

# Vérifie la sécurité du nom de fichier /!\ suite à la vulnérabilité Path Traversal /!\
def verifier_securite_nom(nom_fichier: str) -> bool:

    if not nom_fichier or nom_fichier.strip() == "":
        return False
        
    # On interdit de remonter dans les dossiers ou de changer de dossier
    if ".." in nom_fichier or "/" in nom_fichier or "\\" in nom_fichier:
        print(f"[ALERTE SÉCURITÉ] Tentative de Path Traversal bloquée : {nom_fichier}")
        return False
        
    return True

# Obtient le chemin complet d'un fichier dans le dossier passwords/
def obtenir_chemin(nom_fichier: str) -> str:
    return os.path.join(DOSSIER_DATA, nom_fichier)

# Lit un fichier binaire depuis le dossier passwords/
def lire_fichier_binaire(nom_fichier: str):

    if not verifier_securite_nom(nom_fichier):
        return False
    
    chemin = obtenir_chemin(nom_fichier)
    if not os.path.exists(chemin):
        return None
    try:
        with open(chemin, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"Erreur lecture : {e}")
        return None

# Écrit un fichier binaire dans le dossier passwords/
def ecrire_fichier_binaire(nom_fichier: str, donnees: bytes):

    if not verifier_securite_nom(nom_fichier):
        return False
    
    init_dossier() # On s'assure que le dossier existe
    chemin = obtenir_chemin(nom_fichier)
    try:
        with open(chemin, 'wb') as f:
            f.write(donnees)
        return True
    except Exception as e:
        print(f"Erreur écriture : {e}")
        return False

# Supprime un fichier binaire du dossier passwords/
def supprimer_fichier_binaire(nom_fichier: str) -> bool:

    if not verifier_securite_nom(nom_fichier):
        return False
    
    # Supprime définitivement un fichier du coffre.
    chemin = obtenir_chemin(nom_fichier)
    
    if os.path.exists(chemin):
        try:
            os.remove(chemin)
            return True
        except Exception as e:
            print(f"Erreur suppression : {e}")
            return False
    return False

# Liste tous les fichiers dans le dossier passwords/
def lister_fichiers():
    if not os.path.exists(DOSSIER_DATA):
        return []
    return [f for f in os.listdir(DOSSIER_DATA) if f.endswith('.crypt') and f != 'auth.crypt']