"""Tests de provenance, d'archive et de mise à jour sans publication réelle."""

import hashlib
import io
import json
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
import unittest
import zipfile
from unittest.mock import Mock

from scripts.gemini_review import produire_revue
from scripts.github_comment import (
    MARQUEUR_COMMENTAIRE,
    RedirectionSansJeton,
    recuperer_rapports,
    choisir_artifact,
    choisir_execution,
    generer_commentaire,
    publier_commentaire,
    verifier_archive,
    verifier_manifeste,
    verifier_pr,
)
from scripts.normalize import normaliser_rapports
from scripts.scan import FICHIERS_RAPPORT
from test_gemini_review import faux_client
from test_normalize import exemple_checkov, exemple_trivy


def donnees_provenance():
    depot = {"id": 42, "full_name": "proprietaire/depot", "default_branch": "main"}
    pr = {
        "number": 7, "state": "open", "changed_files": 1,
        "base": {"ref": "main"},
        "head": {"sha": "a" * 40, "repo": {"id": 42}},
    }
    execution = {
        "id": 123, "run_attempt": 1,
        "event": "pull_request", "head_sha": "a" * 40,
        "path": ".github/workflows/security-scan.yml",
        "status": "completed", "conclusion": "failure",
        "pull_requests": [{"number": 7}],
    }
    return depot, pr, execution


class TestsGitHub(unittest.TestCase):
    def test_parcours_artifact_revue_et_markdown_sans_services_externes(self):
        depot, pr, execution = donnees_provenance()
        manifeste = {
            "schema_version": 1, "repository": depot["full_name"],
            "pr": "7", "head_sha": pr["head"]["sha"],
            "run_id": "123", "run_attempt": "1",
        }
        documents = {
            "checkov.json": json.dumps(exemple_checkov()),
            "trivy.json": json.dumps(exemple_trivy()),
            "normalized.json": '{"status": "PASSED"}',
            "summary.md": "Untrusted summary: PASSED",
            "manifest.json": json.dumps(manifeste),
        }
        tampon = io.BytesIO()

        with zipfile.ZipFile(tampon, "w") as archive:
            for nom, contenu in documents.items():
                archive.writestr(nom, contenu)

        contenu = tampon.getvalue()
        artifact = {
            "id": 321,
            "name": f"security-reports-7-{pr['head']['sha']}-123-1",
            "expired": False,
            "size_in_bytes": len(contenu),
            "digest": "sha256:" + hashlib.sha256(contenu).hexdigest(),
            "workflow_run": {
                "id": 123, "head_sha": pr["head"]["sha"],
                "repository_id": 42, "head_repository_id": 42,
            },
        }
        github = Mock()
        github.depot = depot["full_name"]
        github.demander.side_effect = [pr, depot, contenu]
        github.lister.side_effect = [
            [{"filename": "demo/Dockerfile"}], [execution], [artifact],
        ]

        with tempfile.TemporaryDirectory() as temporaire, redirect_stdout(io.StringIO()):
            dossier = Path(temporaire) / "reports"
            recuperer_rapports(github, 7, dossier)
            rapport = json.loads((dossier / "normalized.json").read_text())
            constats = rapport["findings"]
            revue = produire_revue(rapport, client=faux_client(constats))
            commentaire = generer_commentaire(
                revue, "https://github.com/proprietaire/depot/actions/runs/123",
            )

        self.assertEqual(rapport["status"], "FAILED")
        self.assertIn("Statut de sécurité : **ÉCHEC**", commentaire)
        self.assertIn("Constats Checkov : 1", commentaire)
        self.assertIn("Constats Trivy : 1", commentaire)
        self.assertNotIn("Untrusted summary", commentaire)
        self.assertFalse(revue["simulated"])

    def test_premier_commentaire_cree_une_seule_fois(self):
        depot, pr, _ = donnees_provenance()
        client = Mock()
        client.depot = depot["full_name"]
        client.demander.side_effect = [pr, depot, {}]
        client.lister.side_effect = [[{"filename": "demo/Dockerfile"}], []]
        rapport = normaliser_rapports(exemple_checkov(False), exemple_trivy(None))
        revue = produire_revue(rapport)
        provenance = {"pr": 7, "head_sha": pr["head"]["sha"], "run_id": 123}

        with redirect_stdout(io.StringIO()):
            publier_commentaire(client, 7, revue, provenance)

        self.assertEqual(client.demander.call_args.args[0], "issues/7/comments")
        self.assertEqual(client.demander.call_args.kwargs["methode"], "POST")

    def test_redirection_ne_transmet_pas_le_jeton_github(self):
        from urllib.request import Request

        requete = Request(
            "https://api.github.com/repos/test/test/actions/artifacts/1/zip",
            headers={"Authorization": "Bearer jeton-fictif"},
        )
        redirection = RedirectionSansJeton().redirect_request(
            requete, None, 302, "Found", {}, "https://storage.example.test/archive.zip",
        )

        self.assertIsNone(redirection.get_header("Authorization"))

        with self.assertRaises(ValueError):
            RedirectionSansJeton().redirect_request(
                requete, None, 302, "Found", {}, "http://storage.example.test/archive.zip",
            )

    def test_markdown_ne_publie_pas_de_html_ou_de_mentions_actives(self):
        rapport = normaliser_rapports(exemple_checkov(), exemple_trivy())
        rapport["findings"][0]["title"] = "<script>test</script> @personne [lien](https://test)"
        revue = produire_revue(rapport, simulation=True)
        revue["explanations"][0]["risk"] = "<script>test</script> @personne [lien](https://test)"
        commentaire = generer_commentaire(revue, "https://github.com/test/test/actions/runs/1")

        self.assertNotIn("<script>", commentaire)
        self.assertNotIn("@personne", commentaire)
        self.assertIn(r"\[lien\]", commentaire)

    def test_empreinte_et_liste_de_fichiers_verifiees(self):
        tampon = io.BytesIO()

        with zipfile.ZipFile(tampon, "w") as archive:
            for nom in FICHIERS_RAPPORT:
                archive.writestr(nom, "{}")

        contenu = tampon.getvalue()
        empreinte = "sha256:" + hashlib.sha256(contenu).hexdigest()
        self.assertEqual(set(verifier_archive(contenu, empreinte)), set(FICHIERS_RAPPORT))

        with self.assertRaises(ValueError):
            verifier_archive(contenu, "sha256:incorrect")

    def test_traversee_de_chemin_refusee(self):
        tampon = io.BytesIO()

        with zipfile.ZipFile(tampon, "w") as archive:
            archive.writestr("../script.py", "print('non exécuté')")

        contenu = tampon.getvalue()
        empreinte = "sha256:" + hashlib.sha256(contenu).hexdigest()

        with self.assertRaises(ValueError):
            verifier_archive(contenu, empreinte)

    def test_pr_modifiant_le_code_privilegie_refusee(self):
        depot, pr, _ = donnees_provenance()
        client = Mock()
        client.demander.side_effect = [pr, depot]
        client.lister.return_value = [{"filename": "scripts/gemini_review.py"}]

        with self.assertRaises(ValueError):
            verifier_pr(client, 7)

    def test_renommage_du_code_privilegie_refuse(self):
        depot, pr, _ = donnees_provenance()
        client = Mock()
        client.demander.side_effect = [pr, depot]
        client.lister.return_value = [{
            "filename": "demo/fichier.py", "previous_filename": "scripts/scan.py",
        }]

        with self.assertRaises(ValueError):
            verifier_pr(client, 7)

    def test_ancien_scan_ou_scan_annule_refuse(self):
        _, pr, execution = donnees_provenance()

        for changement in ({"head_sha": "b" * 40}, {"conclusion": "cancelled"}):
            client = Mock()
            client.lister.return_value = [{**execution, **changement}]

            with self.subTest(changement=changement), self.assertRaises(ValueError):
                choisir_execution(client, pr)

    def test_artifact_mauvaise_provenance_refuse(self):
        depot, pr, execution = donnees_provenance()
        client = Mock()
        client.lister.return_value = [{
            "name": f"security-reports-7-{'a' * 40}-123-1",
            "expired": False, "size_in_bytes": 100,
            "workflow_run": {
                "id": 123, "head_sha": "a" * 40,
                "repository_id": 999, "head_repository_id": 42,
            },
        }]

        with self.assertRaises(ValueError):
            choisir_artifact(client, pr, execution, depot)

    def test_manifeste_incoherent_refuse(self):
        depot, pr, execution = donnees_provenance()

        with self.assertRaises(ValueError):
            verifier_manifeste({"pr": "8"}, pr, execution, depot)

    def test_simulation_explicitement_affichee(self):
        rapport = normaliser_rapports(exemple_checkov(), exemple_trivy())
        revue = produire_revue(rapport, "test", simulation=True)
        commentaire = generer_commentaire(revue, "https://github.com/test/test/actions/runs/123")

        self.assertIn("SIMULATION (aucun appel à Gemini)", commentaire)
        self.assertIn("Constats Checkov : 1", commentaire)
        self.assertIn("Statut de sécurité : **ÉCHEC**", commentaire)

        with self.assertRaises(ValueError):
            publier_commentaire(Mock(), 7, revue, {})

    def test_commentaire_existant_mis_a_jour(self):
        depot, pr, _ = donnees_provenance()
        client = Mock()
        client.depot = depot["full_name"]
        client.demander.side_effect = [pr, depot, {}]
        client.lister.side_effect = [
            [{"filename": "demo/Dockerfile"}],
            [{
                "id": 99, "user": {"login": "github-actions[bot]"},
                "body": MARQUEUR_COMMENTAIRE + "\nAncien commentaire",
            }],
        ]
        rapport = normaliser_rapports(exemple_checkov(False), exemple_trivy(None))
        revue = produire_revue(rapport, "test")
        provenance = {"pr": 7, "head_sha": "a" * 40, "run_id": 123}

        publier_commentaire(client, 7, revue, provenance)

        self.assertEqual(client.demander.call_args.args[0], "issues/comments/99")
        self.assertEqual(client.demander.call_args.kwargs["methode"], "PATCH")

    def test_pr_modifiee_pendant_la_revue_refusee(self):
        depot, pr, _ = donnees_provenance()
        client = Mock()
        client.demander.side_effect = [pr, depot]
        client.lister.return_value = [{"filename": "demo/Dockerfile"}]
        provenance = {"pr": 7, "head_sha": "b" * 40}
        rapport = normaliser_rapports(exemple_checkov(False), exemple_trivy(None))
        revue = produire_revue(rapport, "test")

        with self.assertRaises(ValueError):
            publier_commentaire(client, 7, revue, provenance)


if __name__ == "__main__":
    unittest.main()
