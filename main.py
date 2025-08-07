"""
Agent MCP Système de Fichiers

Un serveur Model Context Protocol qui fournit des capacités de
navigation et de recherche dans le système de fichiers.
Offre des outils pour lister les fichiers, lire le contenu
et rechercher dans les fichiers et répertoires.
"""

import fnmatch
import re
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("FileSystem Agent")


@dataclass
class FileInfo:
    """Informations sur un fichier ou répertoire"""

    name: str
    path: str
    size: int
    is_directory: bool
    modified_time: float
    permissions: str


@dataclass
class SearchResult:
    """Résultat de recherche avec chemin du fichier, numéro de ligne et contenu correspondant"""

    file_path: str
    line_number: int
    line_content: str
    match_context: str


@mcp.tool()
def list_files(
    directory_path: str = ".", include_hidden: bool = False, pattern: str = "*"
) -> List[FileInfo]:
    """Liste les fichiers et répertoires dans le chemin spécifié.

    Args:
        directory_path: Chemin du répertoire à lister (défaut: répertoire courant)
        include_hidden: Inclure les fichiers/répertoires cachés (défaut: False)
        pattern: Motif glob pour filtrer les fichiers (défaut: "*" pour tous les fichiers)
    """
    try:
        path = Path(directory_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Directory '{directory_path}' does not exist")
        if not path.is_dir():
            raise NotADirectoryError(f"'{directory_path}' is not a directory")

        files = []
        for item in path.iterdir():
            if not include_hidden and item.name.startswith("."):
                continue

            if not fnmatch.fnmatch(item.name, pattern):
                continue

            try:
                stat = item.stat()
                file_info = FileInfo(
                    name=item.name,
                    path=str(item),
                    size=stat.st_size,
                    is_directory=item.is_dir(),
                    modified_time=stat.st_mtime,
                    permissions=oct(stat.st_mode)[-3:],
                )
                files.append(file_info)
            except (OSError, PermissionError):
                continue

        return sorted(files, key=lambda x: (not x.is_directory, x.name.lower()))
    except Exception as e:
        raise RuntimeError(f"Error listing directory: {str(e)}") from e


def _is_text_file(file_path: Path) -> bool:
    """Détermine si un fichier est un fichier texte en lisant les premiers octets."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if not chunk:
                return True  # Fichier vide = texte

            # Vérifier la présence de caractères null
            # (indicateur de fichier binaire)
            if b"\x00" in chunk:
                return False

            # Essayer de décoder en UTF-8
            try:
                chunk.decode("utf-8")
                return True
            except UnicodeDecodeError:
                pass

            # Essayer d'autres encodages courants
            for encoding in ["latin-1", "cp1252", "iso-8859-1"]:
                try:
                    chunk.decode(encoding)
                    return True
                except UnicodeDecodeError:
                    continue

            return False
    except (OSError, IOError, UnicodeDecodeError):
        return False


@mcp.tool()
def read_file(
    file_path: str, max_lines: int = 1000, encoding: str = "utf-8"
) -> Dict[str, Any]:
    """Lit le contenu d'un fichier.

    Args:
        file_path: Chemin du fichier à lire
        max_lines: Nombre maximum de lignes à lire (défaut: 1000)
        encoding: Encodage du fichier (défaut: utf-8)
    """
    try:
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"File '{file_path}' does not exist")
        if path.is_dir():
            raise IsADirectoryError(f"'{file_path}' is a directory, not a file")

        # Vérifier si c'est un fichier texte
        if not _is_text_file(path):
            stat = path.stat()
            return {
                "file_path": str(path),
                "lines": [],
                "total_lines": 0,
                "truncated": False,
                "size_bytes": stat.st_size,
                "encoding": "binary",
                "error": (
                    f"Fichier binaire détecté (extension: {path.suffix}). "
                    "Utilisez un outil spécialisé pour lire ce type de fichier."
                ),
            }

        # Essayer de lire avec l'encodage spécifié
        encodings_to_try = (
            [encoding]
            if encoding != "utf-8"
            else ["utf-8", "latin-1", "cp1252", "iso-8859-1"]
        )

        for enc in encodings_to_try:
            try:
                with open(path, "r", encoding=enc) as f:
                    lines = []
                    for i, line in enumerate(f, 1):
                        if i > max_lines:
                            break
                        lines.append(line.rstrip("\n\r"))

                stat = path.stat()
                return {
                    "file_path": str(path),
                    "lines": lines,
                    "total_lines": len(lines),
                    "truncated": len(lines) == max_lines,
                    "size_bytes": stat.st_size,
                    "encoding": enc,
                }
            except UnicodeDecodeError as exc:
                if enc == encodings_to_try[-1]:  # Dernier encodage testé
                    raise RuntimeError(
                        f"Impossible de décoder le fichier avec les encodages "
                        f"testés: {encodings_to_try}"
                    ) from exc
                continue

    except Exception as e:
        raise RuntimeError(f"Erreur lors de la lecture du fichier: {str(e)}") from e


@mcp.tool()
def search_content(
    search_term: str,
    directory_path: str = ".",
    file_pattern: str = "*",
    case_sensitive: bool = False,
    max_results: int = 100,
) -> List[SearchResult]:
    """Recherche du contenu textuel dans les fichiers.

    Args:
        search_term: Texte à rechercher
        directory_path: Répertoire dans lequel rechercher (défaut: répertoire courant)
        file_pattern: Motif de fichier à correspondre (défaut: "*" pour tous les fichiers)
        case_sensitive: Si la recherche doit être sensible à la casse (défaut: False)
        max_results: Nombre maximum de résultats à retourner (défaut: 100)
    """
    try:
        path = Path(directory_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Directory '{directory_path}' does not exist")

        results = []
        search_lower = search_term.lower() if not case_sensitive else search_term

        def search_file(file_path: Path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        line_to_search = line if case_sensitive else line.lower()
                        if search_lower in line_to_search:
                            context_start = max(0, line_to_search.find(search_lower) - 20)
                            context_end = min(
                                len(line), context_start + len(search_lower) + 40
                            )
                            context = line[context_start:context_end].strip()

                            results.append(
                                SearchResult(
                                    file_path=str(file_path),
                                    line_number=line_num,
                                    line_content=line.strip(),
                                    match_context=context,
                                )
                            )

                            if len(results) >= max_results:
                                return False
                return True
            except (UnicodeDecodeError, PermissionError, OSError):
                return True

        if path.is_file():
            search_file(path)
        else:
            for file_path in path.rglob(file_pattern):
                if file_path.is_file():
                    if not search_file(file_path):
                        break

        return results
    except Exception as e:
        raise RuntimeError(f"Error searching content: {str(e)}") from e


@mcp.tool()
def get_binary_file_info(file_path: str) -> Dict[str, Any]:
    """Obtient des informations sur un fichier binaire.

    Args:
        file_path: Chemin du fichier binaire à analyser
    """
    try:
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"File '{file_path}' does not exist")
        if path.is_dir():
            raise IsADirectoryError(f"'{file_path}' is a directory, not a file")

        stat = path.stat()

        # Lire les premiers octets pour identifier le type
        magic_bytes = b""
        try:
            with open(path, "rb") as f:
                magic_bytes = f.read(16)
        except (OSError, IOError):
            pass

        # Détection basique du type de fichier
        file_type = "Unknown binary"
        if magic_bytes.startswith(b"%PDF"):
            file_type = "PDF Document"
        elif magic_bytes.startswith(b"\x89PNG"):
            file_type = "PNG Image"
        elif magic_bytes.startswith(b"\xff\xd8\xff"):
            file_type = "JPEG Image"
        elif magic_bytes.startswith(b"GIF8"):
            file_type = "GIF Image"
        elif magic_bytes.startswith(b"PK"):
            file_type = "ZIP Archive (ou fichier Office)"
        elif magic_bytes.startswith(b"\x7fELF"):
            file_type = "Executable Linux/Unix"
        elif magic_bytes.startswith(b"MZ"):
            file_type = "Executable Windows"

        return {
            "file_path": str(path),
            "name": path.name,
            "size_bytes": stat.st_size,
            "modified_time": stat.st_mtime,
            "permissions": oct(stat.st_mode)[-3:],
            "extension": path.suffix,
            "detected_type": file_type,
            "magic_bytes_hex": magic_bytes.hex() if magic_bytes else "",
            "is_binary": True,
        }
    except Exception as e:
        raise RuntimeError(f"Erreur lors de l'analyse du fichier binaire: {str(e)}") from e


@mcp.tool()
def read_binary_file(
    file_path: str, max_bytes: int = 1024, offset: int = 0
) -> Dict[str, Any]:
    """Lit le contenu brut d'un fichier binaire.

    Args:
        file_path: Chemin du fichier binaire à lire
        max_bytes: Nombre maximum d'octets à lire (défaut: 1024)
        offset: Position de départ dans le fichier (défaut: 0)
    """
    try:
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"File '{file_path}' does not exist")
        if path.is_dir():
            raise IsADirectoryError(f"'{file_path}' is a directory, not a file")

        stat = path.stat()

        with open(path, "rb") as f:
            if offset > 0:
                f.seek(offset)

            content = f.read(max_bytes)

            # Convertir en représentations lisibles
            hex_content = content.hex()

            # Essayer de créer une représentation ASCII (avec . pour les non-imprimables)
            ascii_repr = ""
            for byte in content:
                if 32 <= byte <= 126:  # Caractères imprimables ASCII
                    ascii_repr += chr(byte)
                else:
                    ascii_repr += "."

            return {
                "file_path": str(path),
                "total_size_bytes": stat.st_size,
                "bytes_read": len(content),
                "offset": offset,
                "hex_content": hex_content,
                "ascii_representation": ascii_repr,
                "truncated": (
                    len(content) == max_bytes and offset + max_bytes < stat.st_size
                ),
            }
    except Exception as e:
        raise RuntimeError(f"Erreur lors de la lecture du fichier binaire: {str(e)}") from e


@mcp.tool()
def extract_text_from_pdf(file_path: str) -> Dict[str, Any]:
    """Extrait le texte d'un fichier PDF (basique, sans dépendances externes)

    Args:
        file_path: Chemin du fichier PDF
    """
    try:
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"File '{file_path}' does not exist")
        if path.suffix.lower() != ".pdf":
            raise ValueError(f"Le fichier '{file_path}' n'est pas un PDF")

        # Lecture basique du PDF pour extraire du texte visible
        text_content = []

        with open(path, "rb") as f:
            content = f.read()

            # Recherche simple de texte dans les streams PDF
            # Cette méthode est très basique et ne fonctionne que pour certains PDFs

            # Chercher les objets de texte dans le PDF
            text_objects = re.findall(rb"BT\s.*?ET", content, re.DOTALL)

            for obj in text_objects:
                # Extraire les chaînes entre parenthèses ou crochets
                strings = re.findall(rb"[\(\[]([^)\]]*?)[\)\]]", obj)
                for s in strings:
                    try:
                        decoded = s.decode("latin-1", errors="ignore")
                        if decoded.strip() and len(decoded) > 2:
                            text_content.append(decoded.strip())
                    except (OSError, IOError, UnicodeDecodeError):
                        continue

        stat = path.stat()
        return {
            "file_path": str(path),
            "size_bytes": stat.st_size,
            "extracted_text_lines": text_content,
            "total_text_fragments": len(text_content),
            "warning": (
                "Extraction basique - certains PDFs peuvent nécessiter "
                "des outils spécialisés comme PyPDF2"
            ),
        }
    except Exception as e:
        raise RuntimeError(f"Erreur lors de l'extraction de texte du PDF: {str(e)}") from e


@mcp.resource("directory://{path}")
def get_directory_info(path: str) -> Dict[str, Any]:
    """Obtient des informations détaillées sur un répertoire"""
    try:
        dir_path = Path(path).resolve()
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory '{path}' does not exist")
        if not dir_path.is_dir():
            raise NotADirectoryError(f"'{path}' is not a directory")

        files = list_files(str(dir_path), include_hidden=True)
        total_size = sum(f.size for f in files if not f.is_directory)

        return {
            "path": str(dir_path),
            "total_files": len([f for f in files if not f.is_directory]),
            "total_directories": len([f for f in files if f.is_directory]),
            "total_size_bytes": total_size,
            "files": [f.__dict__ for f in files],
        }
    except Exception as e:
        raise RuntimeError(f"Error getting directory info: {str(e)}") from e


@mcp.resource("file://{path}")
def get_file_info(path: str) -> Dict[str, Any]:
    """Obtient des informations détaillées sur un fichier"""
    try:
        file_path = Path(path).resolve()
        if not file_path.exists():
            raise FileNotFoundError(f"File '{path}' does not exist")
        if file_path.is_dir():
            raise IsADirectoryError(f"'{path}' is a directory, not a file")

        stat = file_path.stat()

        is_text = True
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                f.read(
                    1024
                )  # Lit les 1024 premiers caractères pour vérifier si c'est un fichier texte
        except UnicodeDecodeError:
            is_text = False

        return {
            "path": str(file_path),
            "name": file_path.name,
            "size_bytes": stat.st_size,
            "modified_time": stat.st_mtime,
            "permissions": oct(stat.st_mode)[-3:],
            "is_text_file": is_text,
            "extension": file_path.suffix,
            "parent_directory": str(file_path.parent),
        }
    except Exception as e:
        raise RuntimeError(f"Error getting file info: {str(e)}") from e


@mcp.prompt()
def generate_internship_report(section: str, content_details: str) -> str:
    """Génère une section du rapport de stage avec directives intégrées

    Args:
        section: Section à générer (ex: "introduction", "contexte", "missions", etc.)
        content_details: Détails spécifiques à inclure dans cette section
    """

    # Directives de rédaction intégrées directement dans le prompt
    directives = """DIRECTIVES DE RÉDACTION OBLIGATOIRES POUR RAPPORT DE STAGE:

STYLE ET STRUCTURE:
- Utiliser un style académique professionnel mais accessible
- Structurer avec des paragraphes courts et aérés (3-5 phrases max)
- Employer la première personne avec parcimonie ("j'ai observé", "j'ai contribué")
- Privilégier les phrases actives et concrètes
- Utiliser des connecteurs logiques pour fluidifier le texte

CONTENU ET APPROCHE:
- Contexturaliser chaque section par rapport à l'entreprise et au secteur
- Intégrer des données chiffrées et exemples concrets quand possible
- Montrer l'évolution/progression de vos compétences
- Faire le lien entre théorie (formation) et pratique (stage)
- Adopter une posture réflexive et analytique

EXIGENCES TECHNIQUES:
- Respecter la terminologie professionnelle du domaine
- Citer les outils, méthodologies et technologies utilisées
- Expliquer les enjeux business/techniques sans jargon excessif
- Inclure une dimension prospective (apprentissages, évolutions)

QUALITÉ RÉDACTIONNELLE:
- Vérifier la cohérence des temps verbaux
- Éviter les répétitions et redondances
- Utiliser un vocabulaire varié et précis
- Soigner les transitions entre idées"""

    return f"""{directives}

==================================================
SECTION À GÉNÉRER: {section.upper()}
DÉTAILS SPÉCIFIQUES: {content_details}

En respectant scrupuleusement les directives ci-dessus, génère maintenant cette section du rapport de stage de manière professionnelle et structurée."""


@mcp.tool()
def update_report_section(
    section: str,
    markdown_file: str,
    new_section_content: str,
    create_if_missing: bool = True,
) -> str:
    """Met à jour une section spécifique dans un fichier Markdown de rapport de stage

    Args:
        section: Section à mettre à jour (ex: "introduction", "contexte", "missions", etc.)
        content_details: Détails spécifiques à inclure dans cette section
        markdown_file: Chemin vers le fichier .md du rapport
        new_section_content: Le nouveau contenu de la section (généré selon les directives)
        create_if_missing: Créer la section si elle n'existe pas (défaut: True)
    """

    try:
        # Vérifier si le fichier existe
        file_path = Path(markdown_file).resolve()
        current_content = ""

        if file_path.exists():
            with open(file_path, "r", encoding="utf-8") as f:
                current_content = f.read()
        elif not create_if_missing:
            return f"ERREUR: Le fichier '{markdown_file}' n'existe pas."

        # Chercher les différents formats de headers possibles
        section_headers = [
            f"# {section.title()}",
            f"## {section.title()}",
            f"### {section.title()}",
            f"# {section.upper()}",
            f"## {section.upper()}",
            f"### {section.upper()}",
            f"# {section.lower()}",
            f"## {section.lower()}",
            f"### {section.lower()}",
        ]

        # Préparer le nouveau contenu avec header
        section_header = f"## {section.title()}"
        formatted_new_content = f"{section_header}\n\n{new_section_content.strip()}\n\n"

        # Chercher si la section existe déjà
        section_found = False
        updated_content = current_content

        for header in section_headers:
            # Pattern pour capturer la section complète
            pattern = rf"({re.escape(header)}.*?)(?=^#{1,3}\s|\Z)"
            match = re.search(pattern, current_content, re.MULTILINE | re.DOTALL)

            if match:
                # Remplacer la section existante
                updated_content = re.sub(
                    pattern,
                    formatted_new_content.rstrip() + "\n\n",
                    current_content,
                    flags=re.MULTILINE | re.DOTALL,
                )
                section_found = True
                break

        # Si la section n'existe pas, l'ajouter à la fin
        if not section_found:
            if current_content and not current_content.endswith("\n\n"):
                updated_content = (
                    current_content.rstrip() + "\n\n" + formatted_new_content
                )
            else:
                updated_content = current_content + formatted_new_content

        # Écrire le contenu modifié
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(updated_content)

        # Retourner le statut de la modification
        action = "modifiée" if section_found else "ajoutée"
        return f"""✅ MODIFICATION EFFECTUÉE

Fichier: {markdown_file}
Section: {section.title()} ({action})
Taille du nouveau contenu: {len(new_section_content)} caractères

Le fichier a été mis à jour avec succès."""

    except Exception as e:
        return f"Erreur lors de la modification du fichier: {str(e)}"


@mcp.tool()
def get_report_section_instructions(
    section: str, content_details: str, markdown_file: str
) -> str:
    """Obtient les instructions pour rédiger une section 
    de rapport (à utiliser avant update_report_section)

    Args:
        section: Section à rédiger (ex: "introduction", "contexte", "missions", etc.)
        content_details: Détails spécifiques à inclure dans cette section
        markdown_file: Chemin vers le fichier .md du rapport (pour contexte)
    """

    # Utiliser le prompt intégré pour générer les instructions
    prompt_instructions = generate_internship_report(section, content_details)

    # Lire le fichier actuel pour contexte
    current_content = ""
    try:
        file_path = Path(markdown_file).resolve()
        if file_path.exists():
            with open(file_path, "r", encoding="utf-8") as f:
                current_content = f.read()
    except Exception:
        pass

    result = f"""📝 INSTRUCTIONS POUR RÉDACTION DE SECTION

FICHIER CIBLE: {markdown_file}
SECTION: {section.upper()}

CONTENU ACTUEL DU FICHIER:
{'-' * 50}
{current_content if current_content else '[Fichier vide ou inexistant]'}
{'-' * 50}

{prompt_instructions}

⚠️ ÉTAPES SUIVANTES:
1. Rédigez le contenu de la section selon les directives ci-dessus
2. Utilisez ensuite l'outil 'update_report_section' avec le contenu rédigé"""

    return result
