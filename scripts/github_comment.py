"""Vérifier les rapports GitHub et créer ou mettre à jour le commentaire de la PR."""

import argparse
import hashlib
import html
import io
import json
import os
import re
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from scripts.normalize import LIBELLES_GRAVITE, charger_json, normaliser_rapports
from scripts.scan import FICHIERS_RAPPORT, enregistrer_json


MARQUEUR_COMMENTAIRE = "<!-- ai-devsecops-guardian:v1 -->"
CHEMIN_WORKFLOW = ".github/workflows/security-scan.yml"
TAILLE_MAX_ARCHIVE = 25 * 1024 * 1024
TAILLE_MAX_DECOMPRESSEE = 45 * 1024 * 1024


class RedirectionSansJeton(urllib.request.HTTPRedirectHandler):
    # Nom imposé par urllib : retirer l'autorisation avant toute redirection.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise ValueError("Redirection non HTTPS interdite")

        redirection = super().redirect_request(req, fp, code, msg, headers, newurl)
        redirection.remove_header("Authorization")

        return redirection


class ClientGitHub:
    def __init__(self, depot, jeton):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", depot):
            raise ValueError("Nom de dépôt invalide")

        self.depot = depot
        self.jeton = jeton
        self.ouvreur = urllib.request.build_opener(RedirectionSansJeton())

    def demander(self, chemin, *, methode="GET", donnees=None, archive=False):
        adresse = f"https://api.github.com/repos/{self.depot}/{chemin}".rstrip("/")
        entetes = {
            "Authorization": f"Bearer {self.jeton}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ai-devsecops-guardian",
        }
        contenu = None

        if donnees is not None:
            contenu = json.dumps(donnees).encode()
            entetes["Content-Type"] = "application/json"

        requete = urllib.request.Request(
            adresse, data=contenu, headers=entetes, method=methode,
        )
        limite = TAILLE_MAX_ARCHIVE if archive else 5 * 1024 * 1024

        with self.ouvreur.open(requete, timeout=90) as reponse:
            resultat = reponse.read(limite + 1)

        if len(resultat) > limite:
            raise ValueError("Réponse GitHub trop volumineuse")

        return resultat if archive else json.loads(resultat)

    def lister(self, chemin, cle=None):
        elements = []
        separateur = "&" if "?" in chemin else "?"

        for page in range(1, 11):
            reponse = self.demander(f"{chemin}{separateur}per_page=100&page={page}")
            lot = reponse[cle] if cle else reponse
            elements.extend(lot)

            if len(lot) < 100:
                return elements

        raise ValueError("Trop de résultats GitHub pour ce POC")


def verifier_pr(client, numero):
    pr = client.demander(f"pulls/{numero}")
    depot = client.demander("")

    if pr["state"] != "open" or pr["base"]["ref"] != depot["default_branch"]:
        raise ValueError("La PR doit être ouverte vers la branche principale")

    if pr["head"]["repo"] is None or pr["head"]["repo"]["id"] != depot["id"]:
        raise ValueError("Ce POC accepte uniquement les PR du même dépôt")

    fichiers = client.lister(f"pulls/{numero}/files")

    if len(fichiers) != pr["changed_files"] or not fichiers:
        raise ValueError("Liste des fichiers de PR incomplète ou vide")

    for fichier in fichiers:
        chemins = [fichier["filename"]]

        if fichier.get("previous_filename"):
            chemins.append(fichier["previous_filename"])

        for chemin in chemins:
            if not chemin.startswith("demo/") or ".." in chemin.split("/"):
                raise ValueError(
                    "La revue privilégiée accepte seulement les changements dans demo/"
                )

    return pr, depot


def choisir_execution(client, pr):
    parametres = urlencode({"event": "pull_request", "head_sha": pr["head"]["sha"]})
    executions = client.lister(
        f"actions/workflows/security-scan.yml/runs?{parametres}", "workflow_runs",
    )
    candidates = []

    for execution in executions:
        numeros_pr = {element["number"] for element in execution.get("pull_requests", [])}

        if pr["number"] in numeros_pr:
            candidates.append(execution)

    if not candidates:
        raise ValueError("Aucun scan associé au commit actuel de cette PR")

    execution = max(candidates, key=lambda element: (element["id"], element["run_attempt"]))

    if execution["status"] != "completed" or execution["conclusion"] not in ("success", "failure"):
        raise ValueError("Le dernier scan doit être terminé, sans annulation")

    if execution["event"] != "pull_request" or execution["head_sha"] != pr["head"]["sha"]:
        raise ValueError("L'événement ou le commit du scan ne correspond pas")

    if execution["path"].split("@")[0] != CHEMIN_WORKFLOW:
        raise ValueError("Le workflow du scan ne correspond pas")

    return execution


def choisir_artifact(client, pr, execution, depot):
    nom = (
        f"security-reports-{pr['number']}-{pr['head']['sha']}-"
        f"{execution['id']}-{execution['run_attempt']}"
    )
    artifacts = client.lister(
        f"actions/runs/{execution['id']}/artifacts", "artifacts",
    )
    correspondances = [artifact for artifact in artifacts if artifact["name"] == nom]

    if len(correspondances) != 1:
        raise ValueError("Artifact de scan absent ou ambigu")

    artifact = correspondances[0]
    origine = artifact.get("workflow_run", {})
    provenance_valide = (
        origine.get("id") == execution["id"]
        and origine.get("head_sha") == pr["head"]["sha"]
        and origine.get("repository_id") == depot["id"]
        and origine.get("head_repository_id") == depot["id"]
    )

    if artifact["expired"] or not provenance_valide:
        raise ValueError("Artifact expiré ou provenance incohérente")

    if artifact["size_in_bytes"] > TAILLE_MAX_ARCHIVE:
        raise ValueError("Artifact trop volumineux")

    return artifact


def verifier_archive(contenu, empreinte_attendue):
    empreinte = "sha256:" + hashlib.sha256(contenu).hexdigest()

    if empreinte != empreinte_attendue:
        raise ValueError("L'empreinte SHA-256 de l'artifact ne correspond pas")

    documents = {}

    with zipfile.ZipFile(io.BytesIO(contenu)) as archive:
        membres = archive.infolist()
        noms = [membre.filename for membre in membres]

        if len(noms) != len(FICHIERS_RAPPORT) or set(noms) != set(FICHIERS_RAPPORT):
            raise ValueError("Contenu de l'archive inattendu ou noms en double")

        if sum(membre.file_size for membre in membres) > TAILLE_MAX_DECOMPRESSEE:
            raise ValueError("Archive décompressée trop volumineuse")

        for membre in membres:
            if membre.file_size > 20 * 1024 * 1024:
                raise ValueError("Rapport trop volumineux dans l'archive")

            # Lecture en mémoire : aucun chemin de l'archive n'est exécuté ou extrait.
            documents[membre.filename] = archive.read(membre)

    return documents


def verifier_manifeste(manifeste, pr, execution, depot):
    attentes = {
        "schema_version": 1,
        "repository": depot["full_name"],
        "pr": str(pr["number"]),
        "head_sha": pr["head"]["sha"],
        "run_id": str(execution["id"]),
        "run_attempt": str(execution["run_attempt"]),
    }

    for cle, valeur in attentes.items():
        if manifeste.get(cle) != valeur:
            raise ValueError(f"Manifeste incohérent : {cle}")


def recuperer_rapports(client, numero, dossier):
    pr, depot = verifier_pr(client, numero)
    execution = choisir_execution(client, pr)
    artifact = choisir_artifact(client, pr, execution, depot)
    contenu = client.demander(f"actions/artifacts/{artifact['id']}/zip", archive=True)
    documents = verifier_archive(contenu, artifact.get("digest"))
    manifeste = json.loads(documents["manifest.json"])

    verifier_manifeste(manifeste, pr, execution, depot)
    rapport = normaliser_rapports(
        json.loads(documents["checkov.json"]),
        json.loads(documents["trivy.json"]),
    )
    provenance = {
        "pr": numero,
        "head_sha": pr["head"]["sha"],
        "run_id": execution["id"],
        "run_url": f"https://github.com/{client.depot}/actions/runs/{execution['id']}",
    }
    dossier.mkdir(parents=True, exist_ok=False)

    for nom in ("checkov.json", "trivy.json", "manifest.json"):
        (dossier / nom).write_bytes(documents[nom])

    # Recalculer le résultat ; ne jamais croire le résumé fourni par l'artifact.
    enregistrer_json(dossier / "normalized.json", rapport)
    enregistrer_json(dossier / "provenance.json", provenance)
    print(f"Rapports vérifiés pour la PR {numero}, exécution {execution['id']}")


def echapper_markdown(texte):
    texte = html.escape(str(texte), quote=False).replace("@", "@\u200b")

    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", texte)


def generer_commentaire(revue, adresse_execution):
    rapport = revue["report"]
    compteurs = rapport["counts"]
    titre = "Revue de sécurité IA"

    if revue["simulated"]:
        titre += " — SIMULATION (aucun appel à Gemini)"

    lignes = [
        MARQUEUR_COMMENTAIRE,
        f"## {titre}",
        "",
        f"- Statut de sécurité : **{'ÉCHEC' if rapport['status'] == 'FAILED' else 'RÉUSSI'}**",
        f"- Constats Checkov : {compteurs['checkov']}",
        f"- Constats Trivy : {compteurs['trivy']}",
        f"- Critiques : {compteurs['critical']}",
        f"- Élevées : {compteurs['high']}",
        "",
        "Les scanners déterminent le statut. Le développeur doit vérifier les conseils de l’IA.",
        "La gravité Checkov est indiquée « NON FOURNIE » si elle est absente du rapport.",
        "",
    ]
    explications = {element["id"]: element for element in revue["explanations"]}

    for constat in revue["selected_findings"]:
        explication = explications[constat["id"]]
        reference = echapper_markdown(constat["scanner_id"])
        gravite = LIBELLES_GRAVITE[constat["severity"]]
        titre_constat = "Configuration Terraform à corriger"

        if constat["scanner"] == "Trivy":
            paquet = echapper_markdown(constat["package"])
            titre_constat = f"Vulnérabilité du paquet {paquet}"
        lignes.extend([
            f"### {reference} — {gravite} ({constat['scanner']})",
            "",
            titre_constat,
            "",
        ])

        if constat["scanner"] == "Trivy":
            paquet = echapper_markdown(constat["package"])
            version = echapper_markdown(constat["installed_version"])
            correction = echapper_markdown(constat["fixed_version"] or "non fournie")
            lignes.append(
                f"Paquet : {paquet} ; version installée : {version} ; "
                f"correction du scanner : {correction}"
            )
        else:
            alias = echapper_markdown(constat["location"])
            debut, fin = constat["lines"]
            lignes.append(f"Alias du fichier : {alias} ; lignes du scanner : {debut}–{fin}")

        lignes.append("")

        for etiquette, cle in (
            ("Risque", "risk"), ("Impact potentiel", "impact"),
            ("Correction recommandée", "recommendation"), ("Incertitude", "uncertainty"),
        ):
            lignes.append(f"- **{etiquette} :** {echapper_markdown(explication[cle])}")

        lignes.append("")

    for raison in rapport["policy_reasons"]:
        lignes.append(f"- Règle de blocage : {echapper_markdown(raison)}")

    mesures = revue["metrics"]
    lignes.extend([
        "",
        f"Constats analysés : {mesures['findings_analyzed']}",
    ])

    for cle, etiquette in (
        ("duration_seconds", "Durée de l’appel IA (s)"),
        ("input_tokens", "Tokens en entrée"),
        ("output_tokens", "Tokens en sortie"),
        ("thinking_tokens", "Tokens de réflexion"),
    ):
        if mesures[cle] is not None:
            lignes.append(f"- {etiquette} : {mesures[cle]}")

    if not revue["selected_findings"]:
        lignes.extend(["", "Aucun constat à expliquer ; Gemini n’a pas été appelé."])

    lignes.extend(["", f"[Exécution du scan de sécurité]({adresse_execution})", ""])

    return "\n".join(lignes)


def publier_commentaire(client, numero, revue, provenance):
    if revue["simulated"]:
        raise ValueError("Publication d'une simulation interdite")

    pr, _ = verifier_pr(client, numero)

    if provenance["pr"] != numero or provenance["head_sha"] != pr["head"]["sha"]:
        raise ValueError("La PR a changé : relancer le scan et la revue")

    adresse = f"https://github.com/{client.depot}/actions/runs/{provenance['run_id']}"
    commentaire = generer_commentaire(revue, adresse)
    commentaires = client.lister(f"issues/{numero}/comments")
    existants = [
        element for element in commentaires
        if element["user"]["login"] == "github-actions[bot]"
        and element["body"].startswith(MARQUEUR_COMMENTAIRE)
    ]

    if existants:
        identifiant = min(existants, key=lambda element: element["id"])["id"]
        client.demander(
            f"issues/comments/{identifiant}", methode="PATCH", donnees={"body": commentaire},
        )
    else:
        client.demander(f"issues/{numero}/comments", methode="POST", donnees={"body": commentaire})

    print(f"Commentaire de sécurité mis à jour sur la PR {numero}")


def principal():
    analyseur = argparse.ArgumentParser(description=__doc__)
    analyseur.add_argument("action", choices=("recuperer", "publier", "apercu"))
    analyseur.add_argument("--pr", type=int)
    analyseur.add_argument("--rapports", default="reports")
    analyseur.add_argument("--revue", default="reports/review.json")
    options = analyseur.parse_args()
    dossier = Path(options.rapports)

    if options.action == "apercu":
        revue = charger_json(options.revue)
        commentaire = generer_commentaire(revue, "https://github.com/OWNER/REPO/actions")
        (dossier / "comment-preview.md").write_text(commentaire, encoding="utf-8")
        print("Aperçu local créé ; aucun commentaire publié")
        return

    if options.pr is None or options.pr < 1:
        analyseur.error("Un numéro de PR positif est requis")

    client = ClientGitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GH_TOKEN"])

    if options.action == "recuperer":
        recuperer_rapports(client, options.pr, dossier)
    else:
        publier_commentaire(
            client, options.pr, charger_json(options.revue),
            charger_json(dossier / "provenance.json"),
        )


if __name__ == "__main__":
    principal()
