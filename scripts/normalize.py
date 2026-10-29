"""Valider les rapports, limiter les données partagées et appliquer la politique."""

import argparse
import hashlib
import json
import re
import unicodedata
from collections import Counter
from pathlib import Path


TAILLE_MAX_RAPPORT = 20 * 1024 * 1024
ORDRE_GRAVITES = ("CRITICAL", "HIGH", "UNKNOWN", "MEDIUM", "LOW", "INFO")
LIBELLES_GRAVITE = {
    "CRITICAL": "CRITIQUE",
    "HIGH": "ÉLEVÉE",
    "UNKNOWN": "NON FOURNIE",
    "MEDIUM": "MOYENNE",
    "LOW": "FAIBLE",
    "INFO": "INFORMATION",
}

# Les clés JSON et les gravités restent celles des scanners pour l'intégration.
MOTIF_SECRET = re.compile(
    r"AIza[0-9A-Za-z_-]{35}"
    r"|AKIA[A-Z0-9]{16}"
    r"|ASIA[A-Z0-9]{16}"
    r"|gh[pousr]_[A-Za-z0-9_]+"
    r"|github_pat_[A-Za-z0-9_]+"
    r"|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"
    r"|\b\d{12}\b"
    r"|(?i:(?:password|secret|token|api[_-]?key)\s*[:=]\s*\S+)"
)

MOTIF_REGLE_CHECKOV = r"CKV[2]?_[A-Z0-9_]{1,100}"
MOTIF_REGLE_TRIVY = (
    r"(?:CVE-\d{4}-\d{4,}"
    r"|GHSA-[a-z0-9-]{14}"
    r"|[A-Za-z0-9][A-Za-z0-9_.:-]{1,99})"
)


def nettoyer_texte(valeur, limite=300):
    """Masquer les données sensibles courantes et retirer les caractères de contrôle."""
    if not isinstance(valeur, str):
        return ""

    texte = MOTIF_SECRET.sub("[MASQUÉ]", valeur)
    texte = re.sub(r"https?://\S+", "[URL MASQUÉE]", texte)
    texte = unicodedata.normalize("NFC", texte)
    texte = "".join(
        " " if unicodedata.category(caractere).startswith("C") else caractere
        for caractere in texte
    )

    return texte[:limite]


def charger_json(chemin):
    fichier = Path(chemin)

    if fichier.is_symlink() or not fichier.is_file():
        raise ValueError("Rapport JSON absent ou lien symbolique interdit")

    if fichier.stat().st_size > TAILLE_MAX_RAPPORT:
        raise ValueError("Rapport JSON trop volumineux")

    return json.loads(fichier.read_text(encoding="utf-8"))


def valider_identifiant(valeur, motif):
    if not isinstance(valeur, str) or not re.fullmatch(motif, valeur):
        raise ValueError("Identifiant de scanner invalide")

    return valeur


def lire_gravite(valeur):
    # Checkov ne fournit généralement pas de gravité dans sa version libre.
    if valeur is None:
        return "UNKNOWN"

    if isinstance(valeur, dict):
        valeur = valeur.get("name")

    if not isinstance(valeur, str) or valeur.upper() not in ORDRE_GRAVITES:
        raise ValueError("Gravité de scanner invalide")

    return valeur.upper()


def lire_echecs_checkov(rapport):
    if isinstance(rapport, list):
        if len(rapport) != 1:
            raise ValueError("Un seul rapport Terraform est attendu")

        rapport = rapport[0]

    if not isinstance(rapport, dict) or rapport.get("check_type") != "terraform":
        raise ValueError("Le rapport Checkov doit concerner Terraform")

    resultats = rapport.get("results")
    resume = rapport.get("summary")

    if not isinstance(resultats, dict) or not isinstance(resume, dict):
        raise ValueError("Résultats ou résumé Checkov absents")

    echecs = resultats.get("failed_checks")
    erreurs = resultats.get("parsing_errors") or resume.get("parsing_errors", 0)

    if not isinstance(echecs, list) or erreurs:
        raise ValueError("Analyse Checkov incomplète")

    if resume.get("failed") != len(echecs) or resume.get("resource_count", 0) < 1:
        raise ValueError("Comptage Checkov incohérent ou aucune ressource analysée")

    return echecs


def lire_resultats_trivy(rapport):
    if not isinstance(rapport, dict):
        raise ValueError("Rapport Trivy invalide")

    if rapport.get("SchemaVersion") != 2:
        raise ValueError("Le format Trivy attendu est la version 2")

    if rapport.get("ArtifactType") != "container_image":
        raise ValueError("Le rapport Trivy doit concerner une image de conteneur")

    systeme = rapport.get("Metadata", {}).get("OS", {})

    if not isinstance(systeme, dict) or not systeme.get("Family") or not systeme.get("Name"):
        raise ValueError("Informations du système absentes : analyse non vérifiable")

    resultats = rapport.get("Results")

    if not isinstance(resultats, list) or not resultats:
        raise ValueError("Résultats de paquets Trivy absents")

    return resultats, systeme


def valider_lignes(lignes):
    if not isinstance(lignes, list) or len(lignes) != 2:
        raise ValueError("Plage de lignes Checkov invalide")

    for numero in lignes:
        if type(numero) is not int or not 1 <= numero <= 1_000_000:
            raise ValueError("Numéro de ligne Checkov invalide")

    if lignes[0] > lignes[1]:
        raise ValueError("Plage de lignes Checkov inversée")

    return lignes


def normaliser_checkov(echecs):
    constats = []
    alias_fichiers = {}

    for echec in echecs:
        regle = valider_identifiant(echec.get("check_id"), MOTIF_REGLE_CHECKOV)
        chemin = echec.get("file_path")

        if not isinstance(chemin, str) or not chemin:
            raise ValueError("Chemin du fichier Checkov absent")

        # Transmettre un alias au modèle, jamais un nom arbitraire issu de la PR.
        if chemin not in alias_fichiers:
            alias_fichiers[chemin] = f"terraform-file-{len(alias_fichiers) + 1}"

        constat = {
            "scanner": "Checkov",
            "scanner_id": regle,
            "title": nettoyer_texte(echec.get("check_name")),
            "severity": lire_gravite(echec.get("severity")),
            "location": alias_fichiers[chemin],
            "lines": valider_lignes(echec.get("file_line_range")),
        }
        constats.append(constat)

    return constats


def normaliser_trivy(resultats):
    constats = []

    for resultat in resultats:
        if not isinstance(resultat, dict):
            raise ValueError("Résultat Trivy invalide")

        vulnerabilites = resultat.get("Vulnerabilities", [])

        if vulnerabilites is None:
            vulnerabilites = []

        if not isinstance(vulnerabilites, list):
            raise ValueError("Liste de vulnérabilités Trivy invalide")

        for vulnerabilite in vulnerabilites:
            regle = valider_identifiant(
                vulnerabilite.get("VulnerabilityID"),
                MOTIF_REGLE_TRIVY,
            )
            paquet = nettoyer_texte(vulnerabilite.get("PkgName"), limite=128)

            if not paquet:
                raise ValueError("Nom du paquet absent")

            constat = {
                "scanner": "Trivy",
                "scanner_id": regle,
                "title": nettoyer_texte(vulnerabilite.get("Title")) or regle,
                "severity": lire_gravite(vulnerabilite.get("Severity")),
                "location": "container-image",
                "package": paquet,
                "installed_version": nettoyer_texte(
                    vulnerabilite.get("InstalledVersion"), limite=100,
                ),
                "fixed_version": nettoyer_texte(
                    vulnerabilite.get("FixedVersion"), limite=100,
                ),
            }
            constats.append(constat)

    return constats


def cle_priorite(constat):
    return (
        ORDRE_GRAVITES.index(constat["severity"]),
        constat["scanner"],
        constat["scanner_id"],
        constat["id"],
    )


def dedoublonner_constats(constats):
    constats_uniques = {}

    for constat in constats:
        contenu = json.dumps(constat, sort_keys=True)
        empreinte = hashlib.sha256(contenu.encode()).hexdigest()[:20]
        constat["id"] = f"f-{empreinte}"
        constats_uniques[constat["id"]] = constat

    return sorted(constats_uniques.values(), key=cle_priorite)


def determiner_blocages(constats, systeme):
    raisons = []

    if any(constat["scanner"] == "Checkov" for constat in constats):
        raisons.append("Checkov contient des contrôles en échec, même sans gravité fournie")

    for constat in constats:
        if constat["scanner"] == "Trivy" and constat["severity"] in ("CRITICAL", "HIGH"):
            raisons.append("Trivy contient des vulnérabilités élevées ou critiques, même sans correctif")
            break

    if systeme.get("EOSL") is True:
        raisons.append("Le système de l’image est en fin de support")

    return raisons


def normaliser_rapports(rapport_checkov, rapport_trivy):
    echecs_checkov = lire_echecs_checkov(rapport_checkov)
    resultats_trivy, systeme = lire_resultats_trivy(rapport_trivy)

    constats = normaliser_checkov(echecs_checkov)
    constats.extend(normaliser_trivy(resultats_trivy))
    constats = dedoublonner_constats(constats)

    par_scanner = Counter(constat["scanner"] for constat in constats)
    par_gravite = Counter(constat["severity"] for constat in constats)
    raisons = determiner_blocages(constats, systeme)

    return {
        "schema_version": 1,
        "status": "FAILED" if raisons else "PASSED",
        "policy_reasons": raisons,
        "counts": {
            "checkov": par_scanner["Checkov"],
            "trivy": par_scanner["Trivy"],
            "critical": par_gravite["CRITICAL"],
            "high": par_gravite["HIGH"],
        },
        "os_end_of_support": systeme.get("EOSL") is True,
        "findings": constats,
    }


def selectionner_constats(rapport):
    """Garder au plus cinq constats, en représentant les deux scanners si possible."""
    selection = []

    for scanner in ("Checkov", "Trivy"):
        for constat in rapport["findings"]:
            if constat["scanner"] == scanner:
                selection.append(constat)
                break

    for constat in rapport["findings"]:
        if len(selection) >= 5:
            break

        if constat not in selection:
            selection.append(constat)

    return selection


def generer_resume_markdown(rapport):
    # Les valeurs techniques du JSON restent stables ; seul l’affichage est traduit.
    compteurs = rapport["counts"]
    lignes = [
        "## Analyse de sécurité",
        "",
        f"Statut de sécurité : **{'ÉCHEC' if rapport['status'] == 'FAILED' else 'RÉUSSI'}**",
        "",
        "| Constats Checkov | Constats Trivy | Critiques | Élevées |",
        "|---:|---:|---:|---:|",
        (
            f"| {compteurs['checkov']} | {compteurs['trivy']} "
            f"| {compteurs['critical']} | {compteurs['high']} |"
        ),
        "",
    ]

    for raison in rapport["policy_reasons"]:
        lignes.append(f"- {raison}")

    lignes.extend([
        "",
        "Les doublons identiques sont retirés ; Checkov peut ne pas fournir de gravité.",
        "",
    ])

    return "\n".join(lignes)


def principal():
    analyseur = argparse.ArgumentParser(description=__doc__)
    analyseur.add_argument("--reports", "--rapports", default="reports")
    analyseur.add_argument("--gate", "--verifier", action="store_true")
    options = analyseur.parse_args()

    dossier = Path(options.reports)
    rapport = normaliser_rapports(
        charger_json(dossier / "checkov.json"),
        charger_json(dossier / "trivy.json"),
    )
    resume = generer_resume_markdown(rapport)

    (dossier / "normalized.json").write_text(
        json.dumps(rapport, indent=2) + "\n", encoding="utf-8",
    )
    (dossier / "summary.md").write_text(resume, encoding="utf-8")

    print(resume)

    if options.gate and rapport["status"] == "FAILED":
        raise SystemExit(1)


if __name__ == "__main__":
    principal()
