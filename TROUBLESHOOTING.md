# Dépannage Agent MCP File System

## Problème : PyPDF2 non disponible dans Claude Desktop

### Symptômes
- L'extraction PDF fonctionne en local (`uv run mcp dev main.py`) 
- Mais échoue dans Claude Desktop avec le message :
```json
{
  "method": "Extraction basique (fallback)",
  "warning": "PyPDF2 non disponible - extraction basique utilisée"
}
```
- Le texte extrait est vide ou très limité

### Cause
Claude Desktop utilise l'interpréteur Python global du système, pas l'environnement virtuel du projet. Les dépendances installées avec `uv` ne sont pas accessibles.

### Solution

#### 1. Installer PyPDF2 globalement
```bash
pip3 install --break-system-packages PyPDF2
```

#### 2. Réinstaller l'agent MCP
```bash
uv run mcp install main.py
```

## Autres problèmes courants

### Erreur "externally-managed-environment"
Si vous obtenez cette erreur, c'est que votre système Python est protégé par PEP 668.

**Solutions :**
1. Utiliser `--break-system-packages` (recommandé pour les outils de développement)
2. Ou installer via Homebrew si disponible : `brew install python-pypdf2`

### Permissions insuffisantes
Si l'installation échoue avec des erreurs de permissions :
```bash
sudo pip3 install --break-system-packages PyPDF2
```

### Vérifier l'interpréteur Python utilisé
```bash
python3 -c "import sys; print(sys.executable)"
```

## Notes importantes

- ⚠️  L'utilisation de `--break-system-packages` peut affecter d'autres outils Python
- ✅  Cette solution est nécessaire car Claude Desktop n'a pas accès aux environnements virtuels
- 🔄  Pensez à réinstaller l'agent MCP après chaque modification de dépendances globales