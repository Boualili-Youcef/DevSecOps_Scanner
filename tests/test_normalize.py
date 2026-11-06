"""Tests hors réseau ; les identifiants TEST-* sont des données fictives de test."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.normalize import (
    charger_json,
    constat_prioritaire,
    generer_resume_markdown,
    lire_gravite,
    nettoyer_texte,
    normaliser_rapports,
    selectionner_constats,
)


def exemple_checkov(avec_echec=True):
    echecs = []

    if avec_echec:
        echecs.append({
            "check_id": "CKV_AWS_24",
            "check_name": "Ensure SSH is restricted",
            "file_path": "/main.tf",
            "file_line_range": [12, 27],
        })

    return {
        "check_type": "terraform",
        "results": {"failed_checks": echecs, "parsing_errors": []},
        "summary": {"failed": len(echecs), "resource_count": 1},
    }


def exemple_trivy(gravite="HIGH", fin_support=False):
    vulnerabilites = []

    if gravite:
        vulnerabilites.append({
            "VulnerabilityID": "TEST-001",
            "PkgName": "paquet-test",
            "Title": "Vulnérabilité fictive pour le test",
            "Severity": gravite,
            "InstalledVersion": "1.0",
            "FixedVersion": "1.1",
        })

    return {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "Metadata": {"OS": {"Family": "alpine", "Name": "test", "EOSL": fin_support}},
        "Results": [{"Vulnerabilities": vulnerabilites}],
    }


class TestsNormalisation(unittest.TestCase):
    def test_comptages_et_gravite_checkov_inconnue(self):
        rapport = normaliser_rapports(exemple_checkov(), exemple_trivy())

        self.assertEqual(rapport["status"], "FAILED")
        self.assertEqual(rapport["counts"], {
            "checkov": 1, "trivy": 1, "critical": 0, "high": 1,
        })
        constat_checkov = next(
            constat for constat in rapport["findings"]
            if constat["scanner"] == "Checkov"
        )
        self.assertEqual(constat_checkov["severity"], "UNKNOWN")

    def test_absence_de_constats_autorise_le_controle(self):
        rapport = normaliser_rapports(exemple_checkov(False), exemple_trivy(None))

        self.assertEqual(rapport["status"], "PASSED")
        self.assertEqual(rapport["findings"], [])

    def test_politique_par_gravite(self):
        for gravite in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "INFO"):
            with self.subTest(gravite=gravite):
                rapport = normaliser_rapports(
                    exemple_checkov(False), exemple_trivy(gravite),
                )
                attendu = "FAILED" if gravite in ("CRITICAL", "HIGH") else "PASSED"
                self.assertEqual(rapport["status"], attendu)

    def test_fin_de_support_bloquante_meme_sans_cve(self):
        rapport = normaliser_rapports(
            exemple_checkov(False), exemple_trivy(None, fin_support=True),
        )

        self.assertEqual(rapport["status"], "FAILED")
        self.assertTrue(rapport["os_end_of_support"])

    def test_rapport_checkov_sous_forme_de_liste(self):
        rapport = normaliser_rapports([exemple_checkov()], exemple_trivy())

        self.assertEqual(rapport["counts"]["checkov"], 1)

    def test_rapport_checkov_incomplet_refuse(self):
        for modification in ({"failed": 2}, {"resource_count": 0}, {"parsing_errors": 1}):
            checkov = exemple_checkov()
            checkov["summary"].update(modification)

            with self.subTest(modification=modification), self.assertRaises(ValueError):
                normaliser_rapports(checkov, exemple_trivy())

    def test_rapport_trivy_incomplet_refuse(self):
        for cle in ("SchemaVersion", "ArtifactType", "Metadata", "Results"):
            trivy = exemple_trivy()
            del trivy[cle]

            with self.subTest(cle=cle), self.assertRaises(ValueError):
                normaliser_rapports(exemple_checkov(), trivy)

    def test_numeros_de_lignes_invalides_refuses(self):
        for lignes in ([True, 3], [0, 2], [4, 3], [1], "1-2"):
            checkov = exemple_checkov()
            checkov["results"]["failed_checks"][0]["file_line_range"] = lignes

            with self.subTest(lignes=lignes), self.assertRaises(ValueError):
                normaliser_rapports(checkov, exemple_trivy())

    def test_noms_et_extraits_de_code_non_transmis(self):
        checkov = exemple_checkov()
        echec = checkov["results"]["failed_checks"][0]
        echec["file_path"] = "/nom-prive.tf"
        echec["code_block"] = [[1, "secret-de-test"]]
        rapport = normaliser_rapports(checkov, exemple_trivy())
        texte = json.dumps(rapport)

        self.assertNotIn("nom-prive", texte)
        self.assertNotIn("secret-de-test", texte)
        self.assertIn("terraform-file-1", texte)

    def test_masquage_des_donnees_sensibles(self):
        texte = "personne@example.test token=valeur https://example.test/prive"
        resultat = nettoyer_texte(texte)

        self.assertNotIn("personne@", resultat)
        self.assertNotIn("valeur", resultat)
        self.assertNotIn("https://", resultat)

    def test_masquage_d_une_cle_google(self):
        cle_fictive = "AIza" + "x" * 35

        self.assertEqual(nettoyer_texte(cle_fictive), "[MASQUÉ]")

    def test_accents_preserves_et_controles_unicode_retires(self):
        self.assertEqual(nettoyer_texte("Réseau privé, sécurité maîtrisée"),
                         "Réseau privé, sécurité maîtrisée")
        self.assertNotIn("\u202e", nettoyer_texte("texte\u202ecaché"))

    def test_gravite_invalide_refusee(self):
        with self.assertRaises(ValueError):
            lire_gravite("URGENT")

        self.assertEqual(lire_gravite({"name": "high"}), "HIGH")

    def test_dedoublonnage_et_identifiants_stables(self):
        trivy = exemple_trivy()
        vulnerabilite = trivy["Results"][0]["Vulnerabilities"][0]
        trivy["Results"][0]["Vulnerabilities"].append(copy.deepcopy(vulnerabilite))

        premier = normaliser_rapports(exemple_checkov(), trivy)
        second = normaliser_rapports(exemple_checkov(), trivy)

        self.assertEqual(premier, second)
        self.assertEqual(premier["counts"]["trivy"], 1)

    def test_tous_les_constats_conserves_et_critiques_en_premier(self):
        trivy = exemple_trivy("CRITICAL")
        modele = trivy["Results"][0]["Vulnerabilities"][0]
        trivy["Results"][0]["Vulnerabilities"] = [
            {**modele, "VulnerabilityID": f"TEST-{numero:03}"}
            for numero in range(10)
        ]
        rapport = normaliser_rapports(exemple_checkov(), trivy)
        selection = selectionner_constats(rapport)

        self.assertEqual(len(selection), 11)
        self.assertEqual({constat["scanner"] for constat in selection}, {"Checkov", "Trivy"})
        self.assertTrue(all(c["severity"] == "CRITICAL" for c in selection[:10]))
        self.assertEqual(selection[-1]["scanner"], "Checkov")

    def test_absence_de_gravite_ne_signifie_pas_faible_priorite(self):
        for scanner, gravite, attendu in (
            ("Checkov", "UNKNOWN", True), ("Checkov", "LOW", True),
            ("Trivy", "CRITICAL", True), ("Trivy", "HIGH", True),
            ("Trivy", "UNKNOWN", True), ("Trivy", "MEDIUM", False),
            ("Trivy", "LOW", False),
        ):
            with self.subTest(scanner=scanner, gravite=gravite):
                self.assertEqual(constat_prioritaire({"scanner": scanner, "severity": gravite}), attendu)

    def test_resume_conserve_le_format_github(self):
        rapport = normaliser_rapports(exemple_checkov(), exemple_trivy())
        resume = generer_resume_markdown(rapport)

        self.assertIn("Statut de sécurité : **ÉCHEC**", resume)
        self.assertIn("| 1 | 1 | 0 | 1 |", resume)

    def test_lecture_json_et_refus_des_liens(self):
        with tempfile.TemporaryDirectory() as dossier:
            fichier = Path(dossier) / "rapport.json"
            fichier.write_text('{"valide": true}')
            lien = Path(dossier) / "lien.json"
            lien.symlink_to(fichier)

            self.assertEqual(charger_json(fichier), {"valide": True})
            with self.assertRaises(ValueError):
                charger_json(lien)


if __name__ == "__main__":
    unittest.main()
