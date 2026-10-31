"""Vérifier Gemini sans réseau ni clé réelle, y compris le transport du SDK."""

import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts.gemini_review import (
    creer_client,
    produire_revue,
    valider_reponse,
)
from scripts.normalize import normaliser_rapports, selectionner_constats
from test_normalize import exemple_checkov, exemple_trivy


def rapport_exemple():
    return normaliser_rapports(exemple_checkov(), exemple_trivy())


def explications_exemple(constats):
    return {
        "findings": [{
            "id": constat["id"],
            "risk": "Un service exposé pourrait être accessible.",
            "impact": "Un accès non autorisé pourrait affecter l’application.",
            "recommendation": "Restreindre les accès ou appliquer le correctif fourni par le scanner, puis analyser à nouveau.",
            "uncertainty": "Le contexte de déploiement et l’exploitabilité restent à vérifier.",
        } for constat in constats],
    }


def faux_client(constats):
    client = Mock()
    client.models.generate_content.return_value = SimpleNamespace(
        candidates=[SimpleNamespace(finish_reason="STOP")],
        text=json.dumps(explications_exemple(constats)),
        usage_metadata=SimpleNamespace(
            prompt_token_count=100,
            candidates_token_count=200,
            thoughts_token_count=30,
        ),
    )
    return client


class TestsGemini(unittest.TestCase):
    def test_requete_minimale_et_mesures(self):
        rapport = rapport_exemple()
        constats = selectionner_constats(rapport)
        client = faux_client(constats)

        revue = produire_revue(rapport, client=client)

        client.models.generate_content.assert_called_once()
        appel = client.models.generate_content.call_args.kwargs
        self.assertEqual(appel["model"], "gemini-3.5-flash-lite")
        self.assertEqual(json.loads(appel["contents"]), {"findings": constats})
        self.assertEqual(appel["config"]["response_mime_type"], "application/json")
        self.assertNotIn("tools", appel["config"])
        self.assertEqual(revue["metrics"]["input_tokens"], 100)
        self.assertEqual(revue["metrics"]["output_tokens"], 200)
        self.assertEqual(revue["metrics"]["thinking_tokens"], 30)
        self.assertFalse(revue["simulated"])

    def test_contrat_sdk_avec_transport_http_simule(self):
        try:
            import httpx
            from google import genai
            from google.genai import types
        except ImportError:
            self.skipTest("SDK Gemini réservé à l'environnement de revue")

        rapport = rapport_exemple()
        constats = selectionner_constats(rapport)
        requetes = []

        def simuler_serveur(requete):
            requetes.append(requete)
            return httpx.Response(200, json={
                "candidates": [{
                    "finishReason": "STOP",
                    "content": {
                        "role": "model",
                        "parts": [{"text": json.dumps(explications_exemple(constats))}],
                    },
                }],
                "usageMetadata": {
                    "promptTokenCount": 100,
                    "candidatesTokenCount": 200,
                    "totalTokenCount": 300,
                },
            })

        options = types.HttpOptions(client_args={
            "transport": httpx.MockTransport(simuler_serveur),
            "trust_env": False,
        })
        with genai.Client(
            api_key="cle-fictive-pour-test",
            vertexai=False,
            http_options=options,
        ) as client:
            revue = produire_revue(rapport, client=client)

        self.assertEqual(len(requetes), 1)
        self.assertIn("gemini-3.5-flash-lite:generateContent", str(requetes[0].url))
        self.assertEqual(requetes[0].headers["x-goog-api-key"], "cle-fictive-pour-test")
        corps = json.loads(requetes[0].content)
        schema = corps["generationConfig"]["responseJsonSchema"]
        self.assertEqual(schema["properties"]["findings"]["maxItems"], len(constats))
        self.assertEqual(revue["metrics"]["input_tokens"], 100)

    def test_simulation_ne_demande_pas_de_cle(self):
        with patch.dict(os.environ, {}, clear=True), patch(
            "scripts.gemini_review.creer_client",
        ) as creation:
            revue = produire_revue(rapport_exemple(), simulation=True)

        creation.assert_not_called()
        self.assertTrue(revue["simulated"])
        self.assertIn("SIMULATION", revue["explanations"][0]["risk"])
        self.assertIsNone(revue["metrics"]["input_tokens"])

    def test_aucun_constat_aucun_appel(self):
        rapport = normaliser_rapports(exemple_checkov(False), exemple_trivy(None))

        with patch("scripts.gemini_review.creer_client") as creation:
            revue = produire_revue(rapport)

        creation.assert_not_called()
        self.assertEqual(revue["metrics"]["findings_analyzed"], 0)

    def test_cle_absente_erreur_claire_sans_sdk(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(
            ValueError, "GEMINI_API_KEY absente",
        ):
            creer_client()

    def test_reponses_bloquees_ou_tronquees_refusees(self):
        constats = selectionner_constats(rapport_exemple())

        for raison in ("MAX_TOKENS", "SAFETY", "RECITATION", None):
            client = faux_client(constats)
            client.models.generate_content.return_value.candidates[0].finish_reason = raison

            with self.subTest(raison=raison), self.assertRaises(ValueError):
                produire_revue(rapport_exemple(), client=client)

    def test_aucun_candidat_refuse(self):
        client = faux_client(selectionner_constats(rapport_exemple()))
        client.models.generate_content.return_value.candidates = []

        with self.assertRaises(ValueError):
            produire_revue(rapport_exemple(), client=client)

    def test_metriques_absentes_acceptees_sans_inventer_des_tokens(self):
        client = faux_client(selectionner_constats(rapport_exemple()))
        client.models.generate_content.return_value.usage_metadata = None
        revue = produire_revue(rapport_exemple(), client=client)

        self.assertIsNone(revue["metrics"]["input_tokens"])
        self.assertIsNone(revue["metrics"]["output_tokens"])

    def test_identifiant_inconnu_double_et_constat_omis_refuses(self):
        constats = selectionner_constats(rapport_exemple())
        reponse = explications_exemple(constats)
        inconnue = explications_exemple(constats)
        inconnue["findings"][0]["id"] = "invente"
        doublon = {"findings": [reponse["findings"][0]] * 2}

        for invalide in (inconnue, doublon, {"findings": []}):
            with self.subTest(invalide=invalide), self.assertRaises(ValueError):
                valider_reponse(json.dumps(invalide), constats)

    def test_references_et_fichiers_inventes_refuses(self):
        constats = selectionner_constats(rapport_exemple())

        for texte in ("CVE-2099-99999", "Edit secret.tf", "See line 12", "Voir la ligne 12", "Edit settings.toml"):
            reponse = explications_exemple(constats)
            reponse["findings"][0]["recommendation"] = texte

            with self.subTest(texte=texte), self.assertRaises(ValueError):
                valider_reponse(json.dumps(reponse), constats)

    def test_gravite_ajoutee_et_json_invalide_refuses(self):
        constats = selectionner_constats(rapport_exemple())
        reponse = explications_exemple(constats)
        reponse["findings"][0]["severity"] = "LOW"

        with self.assertRaises(ValueError):
            valider_reponse(json.dumps(reponse), constats)

        with self.assertRaises(ValueError):
            valider_reponse("```json\n{}\n```", constats)

    def test_statut_du_scanner_conserve_apres_revue(self):
        rapport = rapport_exemple()
        client = faux_client(selectionner_constats(rapport))
        revue = produire_revue(rapport, client=client)

        self.assertEqual(revue["report"]["status"], "FAILED")
        self.assertEqual(revue["report"]["counts"], rapport["counts"])



if __name__ == "__main__":
    unittest.main()
