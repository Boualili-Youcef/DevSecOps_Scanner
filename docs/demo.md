# Tester le projet

Depuis la racine du dépôt. Prérequis : Python 3.12, Docker démarré et curl.
Ne jamais exécuter `terraform apply` sur la démonstration.

## 1. Tester en local

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

## 2. Lancer Checkov et Trivy

```bash
python3.12 -m venv .venv-scan
source .venv-scan/bin/activate
python -m pip install -r requirements-scan.txt
bash scripts/install_trivy.sh
python -m scripts.scan --trivy .tools/trivy
python -m scripts.normalize --verifier
```

Les rapports sont dans `reports/`. Le contrôle échoue si des problèmes bloquants sont détectés.

## 3. Vérifier après correction

Après avoir corrigé les fichiers signalés, relancer les scanners pour produire de nouveaux rapports :

```bash
source .venv-scan/bin/activate
python -m scripts.scan --trivy .tools/trivy
python -m scripts.normalize --verifier
```

Le statut doit être **RÉUSSI** si tous les problèmes bloquants ont été corrigés.
