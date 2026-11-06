"""Vérifier Gemini sans réseau ni clé réelle, y compris le transport du SDK."""

import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts.gemini_review import (
    appeler_gemini,
    creer_client,
    produire_revue,
    valider_reponse,
)
from scripts.normalize import normaliser_rapports, selectionner_constats
from test_normalize import exemple_checkov, exemple_trivy


def rapport_exemple():
    return normaliser_rapports(exemple_checkov(), exemple_trivy())


def explications_exemple(constats, *, detaille=True):
    return {
        "findings": [{
            "id": constat["id"],
            **({
                "risk": "Un service exposé pourrait être accessible.",
                "impact": "Un accès non autorisé pourrait affecter l’application.",
                "verification": "Relancer le scanner et vérifier que le contrôle concerné ne signale plus le problème.",
            } if detaille else {
                "summary": "Un paquet présente un problème de sécurité signalé par le scanner.",
            }),
            "recommendation": "Restreindre les accès ou appliquer le correctif fourni par le scanner, puis analyser à nouveau.",
            "uncertainty": "Le contexte de déploiement et l’exploitabilité restent à vérifier.",
        } for constat in constats],
    }


def rapport_mixte(critiques=2, eleves=2, autres=15, *, checkov=True):
    trivy = exemple_trivy()
    modele = trivy["Results"][0]["Vulnerabilities"][0]
    gravites = ["CRITICAL"] * critiques + ["HIGH"] * eleves + ["MEDIUM"] * autres
    trivy["Results"][0]["Vulnerabilities"] = [
        {**modele, "VulnerabilityID": f"TEST-{i:04}", "Severity": gravite}
        for i, gravite in enumerate(gravites)
    ]
    return normaliser_rapports(exemple_checkov(checkov), trivy)


def reponse_exemple(constats, *, detaille=True):
    return SimpleNamespace(
        candidates=[SimpleNamespace(finish_reason="STOP")],
        text=json.dumps(explications_exemple(constats, detaille=detaille)),
        usage_metadata=SimpleNamespace(
            prompt_token_count=100, candidates_token_count=200, thoughts_token_count=30,
        ),
    )


def faux_client(constats):
    client = Mock()
    client.models.generate_content.return_value = reponse_exemple(constats)
    return client


def client_par_lots():
    client = Mock()

    def repondre(**arguments):
        constats = json.loads(arguments["contents"])["findings"]
        proprietes = arguments["config"]["response_json_schema"]["properties"]["findings"]["items"]["properties"]
        return reponse_exemple(constats, detaille="risk" in proprietes)

    client.models.generate_content.side_effect = repondre
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

        rapport = rapport_mixte()
        constats = selectionner_constats(rapport)
        requetes = []

        def simuler_serveur(requete):
            requetes.append(requete)
            corps = json.loads(requete.content)
            envoyes = json.loads(corps["contents"][0]["parts"][0]["text"])["findings"]
            proprietes = corps["generationConfig"]["responseJsonSchema"]["properties"]["findings"]["items"]["properties"]
            return httpx.Response(200, json={
                "candidates": [{
                    "finishReason": "STOP",
                    "content": {
                        "role": "model",
                        "parts": [{"text": json.dumps(explications_exemple(envoyes, detaille="risk" in proprietes))}],
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

        self.assertEqual(len(requetes), 4)
        self.assertIn("gemini-3.5-flash-lite:generateContent", str(requetes[0].url))
        self.assertEqual(requetes[0].headers["x-goog-api-key"], "cle-fictive-pour-test")
        corps = json.loads(requetes[0].content)
        schema = corps["generationConfig"]["responseJsonSchema"]
        self.assertEqual(schema["properties"]["findings"]["maxItems"], 5)
        self.assertEqual(revue["metrics"]["input_tokens"], 400)
        self.assertEqual(revue["metrics"]["findings_analyzed"], 20)
        self.assertEqual(revue["ai_status"], "complete")

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
                appeler_gemini(client, "test", constats)

    def test_aucun_candidat_refuse(self):
        client = faux_client(selectionner_constats(rapport_exemple()))
        client.models.generate_content.return_value.candidates = []

        with self.assertRaises(ValueError):
            appeler_gemini(client, "test", selectionner_constats(rapport_exemple()))

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

    def test_vingt_constats_cinq_detailles_quinze_brefs_sans_omission(self):
        rapport = rapport_mixte()
        original = json.dumps(rapport, sort_keys=True)
        client = client_par_lots()
        revue = produire_revue(rapport, client=client)

        self.assertEqual(client.models.generate_content.call_count, 4)
        self.assertEqual(revue["metrics"]["findings_analyzed"], 20)
        self.assertEqual(revue["metrics"]["findings_fallback"], 0)
        self.assertEqual(revue["metrics"]["output_tokens"], 800)
        self.assertEqual({e["id"] for e in revue["explanations"]}, {c["id"] for c in rapport["findings"]})
        self.assertEqual(sum("verification" in e for e in revue["explanations"]), 5)
        self.assertEqual(sum("summary" in e for e in revue["explanations"]), 15)
        self.assertEqual(json.dumps(rapport, sort_keys=True), original)
        premier_lot = json.loads(client.models.generate_content.call_args_list[0].kwargs["contents"])["findings"]
        self.assertEqual([c["severity"] for c in premier_lot], ["CRITICAL", "CRITICAL", "HIGH", "HIGH", "UNKNOWN"])

    def test_douze_critiques_recoivent_toutes_une_explication_detaillee(self):
        revue = produire_revue(rapport_mixte(12, 0, 0, checkov=False), client=client_par_lots())
        self.assertEqual(revue["metrics"]["batches_attempted"], 3)
        self.assertEqual(len(revue["explanations"]), 12)
        self.assertTrue(all("verification" in e for e in revue["explanations"]))

    def test_budget_limite_les_appels_et_conserve_le_rapport_entier(self):
        client = client_par_lots()
        revue = produire_revue(rapport_mixte(), client=client, max_lots=1)
        self.assertEqual(client.models.generate_content.call_count, 1)
        self.assertEqual(revue["ai_status"], "partial")
        self.assertEqual(revue["issues"], ["budget"])
        self.assertEqual(revue["metrics"]["findings_fallback"], 15)
        self.assertEqual(len(revue["report"]["findings"]), 20)

    def test_delai_epuise_aucun_appel_et_aucun_constat_perdu(self):
        client = client_par_lots()
        with patch("scripts.gemini_review.time.monotonic", side_effect=[0, 301]):
            revue = produire_revue(rapport_mixte(), client=client)
        client.models.generate_content.assert_not_called()
        self.assertEqual(revue["metrics"]["findings_fallback"], 20)
        self.assertEqual(revue["issues"], ["budget"])

    def test_erreur_api_conserve_les_lots_reussis_sans_exposer_l_erreur(self):
        client = client_par_lots()
        premier = client.models.generate_content.side_effect
        appels = []

        def interrompre(**arguments):
            appels.append(arguments)
            if len(appels) == 2:
                raise RuntimeError("API key=valeur-confidentielle-test")
            return premier(**arguments)

        client.models.generate_content.side_effect = interrompre
        revue = produire_revue(rapport_mixte(), client=client)
        self.assertEqual(revue["ai_status"], "partial")
        self.assertEqual(len(revue["explanations"]), 5)
        self.assertEqual(revue["metrics"]["findings_fallback"], 15)
        self.assertEqual(len(appels), 2)
        self.assertNotIn("valeur-confidentielle-test", json.dumps(revue))
        self.assertEqual(revue["report"]["status"], "FAILED")

    def test_cle_absente_repli_sur_scanners_sans_appel_reel(self):
        with patch.dict(os.environ, {}, clear=True):
            revue = produire_revue(rapport_mixte())
        self.assertEqual(revue["ai_status"], "unavailable")
        self.assertEqual(revue["metrics"]["findings_analyzed"], 0)
        self.assertEqual(len(revue["report"]["findings"]), 20)

    def test_reponse_invalide_non_publiee_comme_explication(self):
        client = faux_client(selectionner_constats(rapport_exemple()))
        client.models.generate_content.return_value.text = '{"findings": []}'
        revue = produire_revue(rapport_exemple(), client=client)
        self.assertEqual(revue["explanations"], [])
        self.assertEqual(revue["ai_status"], "unavailable")

    def test_reference_d_un_autre_constat_du_lot_refusee(self):
        constats = selectionner_constats(rapport_exemple())
        reponse = explications_exemple(constats)
        reponse["findings"][0]["recommendation"] = "Corriger CKV_AWS_24"
        self.assertEqual(constats[0]["scanner"], "Trivy")
        with self.assertRaises(ValueError):
            valider_reponse(json.dumps(reponse), constats)

    def test_reponse_breve_trop_longue_ou_incomplete_refusee(self):
        constats = selectionner_constats(rapport_mixte(0, 0, 1, checkov=False))
        reponse = explications_exemple(constats, detaille=False)
        valider_reponse(json.dumps(reponse), constats, detaille=False)
        reponse["findings"][0]["summary"] = "a" * 221
        with self.assertRaises(ValueError):
            valider_reponse(json.dumps(reponse), constats, detaille=False)

    def test_simulation_complete_sans_compter_des_appels_ou_tokens_reels(self):
        revue = produire_revue(rapport_mixte(), simulation=True)
        self.assertEqual(len(revue["explanations"]), 20)
        self.assertEqual(revue["metrics"]["findings_analyzed"], 0)
        self.assertEqual(revue["metrics"]["batches_attempted"], 0)
        self.assertIsNone(revue["metrics"]["input_tokens"])



if __name__ == "__main__":
    unittest.main()
