# --- Fonction d'authentification pour l'utilisateur Root ---
 
from security import crypto
from file_io import manager

AUTH_FILENAME = "auth.crypt"

# Vérifie si l'utilisateur Root est inscrit
def est_inscrit() -> bool:
    return manager.lire_fichier_binaire(AUTH_FILENAME) is not None

# Inscrit l'utilisateur Root avec le mot de passe donné
def inscrire_root(password: str) -> bool:
    try:
        cle_derivee, sel = crypto.deriver_cle(password)
        data = sel + cle_derivee
        return manager.ecrire_fichier_binaire(AUTH_FILENAME, data)
    except Exception as e:
        print(f"Erreur inscription : {e}")
        return False

# Vérifie si le mot de passe est bien celui du Root
def verifier_root(password: str) -> bool:
    data = manager.lire_fichier_binaire(AUTH_FILENAME)
    
    if not data or len(data) < 48:
        return False

    sel_stocke = data[:16]
    hash_stocke = data[16:]

    cle_calculee, _ = crypto.deriver_cle(password, sel=sel_stocke)
    return cle_calculee == hash_stocke