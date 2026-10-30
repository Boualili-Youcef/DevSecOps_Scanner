"""Exécuter les scans et exporter les rapports avant le contrôle de sécurité."""

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from scripts.normalize import (
    charger_json,
    generer_resume_markdown,
    normaliser_rapports,
)


FICHIERS_RAPPORT = (
    "checkov.json",
    "trivy.json",
    "normalized.json",
    "summary.md",
    "manifest.json",
)


def preparer_dossier(dossier):
    dossier.mkdir(parents=True, exist_ok=True)

    # Un ancien rapport ne doit pas faire croire que le nouveau scan a réussi.
    for nom in FICHIERS_RAPPORT:
        (dossier / nom).unlink(missing_ok=True)


def analyser_terraform(demonstration, dossier, environnement):
    commande = [
        "checkov",
        "-d", str(demonstration / "terraform"),
        "--framework", "terraform",
        "--output", "json",
        "--soft-fail",
        "--skip-download",
    ]
    resultat = subprocess.run(
        commande,
        env=environnement,
        capture_output=True,
        timeout=180,
    )
    (dossier / "checkov.json").write_bytes(resultat.stdout)

    if resultat.returncode:
        raise RuntimeError("Échec de Checkov : consulter la sortie locale du scanner")


def construire_image(demonstration):
    numero_execution = os.environ.get("GITHUB_RUN_ID", "local")
    image = f"guardian-demo:{numero_execution}"

    commande = [
        "docker", "build",
        "--network=none",
        "--tag", image,
        str(demonstration),
    ]
    subprocess.run(commande, check=True, timeout=300)

    return image


def analyser_image(image, dossier, executable_trivy):
    commande = [
        executable_trivy, "image",
        "--scanners", "vuln",
        "--no-progress",
        "--format", "json",
        "--output", str(dossier / "trivy.json"),
        "--exit-code", "0",
        "--timeout", "10m",
        image,
    ]
    subprocess.run(commande, check=True, timeout=660)


def lire_sortie(commande, environnement=None):
    return subprocess.check_output(
        commande,
        env=environnement,
        text=True,
    ).strip()


def creer_manifeste(image, executable_trivy, environnement):
    return {
        "schema_version": 1,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "repository": os.environ.get("GITHUB_REPOSITORY", "local"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        "head_sha": os.environ.get("PR_HEAD_SHA", "local"),
        "merge_sha": os.environ.get("GITHUB_SHA", "local"),
        "pr": os.environ.get("PR_NUMBER", "local"),
        "checkov_version": lire_sortie(["checkov", "--version"], environnement),
        "trivy_version": lire_sortie([executable_trivy, "--version"]),
        "image_id": lire_sortie([
            "docker", "image", "inspect",
            "--format", "{{.Id}}", image,
        ]),
    }


def enregistrer_json(chemin, donnees):
    chemin.write_text(json.dumps(donnees, indent=2) + "\n", encoding="utf-8")


def principal():
    analyseur = argparse.ArgumentParser(description=__doc__)
    analyseur.add_argument("--reports", "--rapports", default="reports")
    analyseur.add_argument("--demo", default="demo")
    analyseur.add_argument("--trivy", default="trivy")
    options = analyseur.parse_args()

    dossier = Path(options.reports).resolve()
    demonstration = Path(options.demo).resolve()
    environnement = {
        **os.environ,
        "BC_SKIP_MAPPING": "TRUE",
        "LOG_LEVEL": "ERROR",
    }

    preparer_dossier(dossier)
    analyser_terraform(demonstration, dossier, environnement)
    image = construire_image(demonstration)
    analyser_image(image, dossier, options.trivy)

    rapport = normaliser_rapports(
        charger_json(dossier / "checkov.json"),
        charger_json(dossier / "trivy.json"),
    )
    resume = generer_resume_markdown(rapport)
    manifeste = creer_manifeste(image, options.trivy, environnement)

    enregistrer_json(dossier / "normalized.json", rapport)
    enregistrer_json(dossier / "manifest.json", manifeste)
    (dossier / "summary.md").write_text(resume, encoding="utf-8")

    print(resume)


if __name__ == "__main__":
    principal()
