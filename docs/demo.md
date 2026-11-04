# Installation et démonstration

Depuis la racine du dépôt, après l’installation Python du README.
Ne jamais déployer les ressources Terraform.

## 1. Lancer les scanners localement

```bash
python3.12 -m venv .venv-scan
.venv-scan/bin/python -m pip install -r requirements-scan.txt
bash scripts/install_trivy.sh
PATH="$PWD/.venv-scan/bin:$PATH" .venv-scan/bin/python -m scripts.scan --trivy .tools/trivy
.venv/bin/python -m scripts.normalize --verifier
```

Le dernier contrôle doit échouer sur le scénario vulnérable. Les JSON restent dans `reports/`.

## 2. Configurer Gemini sur GitHub

Dans les paramètres du dépôt, créer l’environnement `gemini-review` :

- Autoriser uniquement la branche `main` dans les règles de déploiement.
- Ajouter le secret d’environnement `GEMINI_API_KEY` avec la clé Gemini.
- Facultatif : définir la variable `GEMINI_MODEL` ; défaut : `gemini-3.5-flash-lite`.

Ne pas utiliser un simple secret de dépôt sans restriction d’environnement.
Les workflows doivent être présents sur `main`. Autoriser la permission `pull-requests: write` déclarée par la revue.

## 3. Ouvrir la PR vulnérable

```bash
git switch main
git switch -c demo/securite
printf '\n# Démonstration de sécurité.\n' >> demo/terraform/main.tf
git add demo/terraform/main.tf
git commit -m "Prépare la démonstration de sécurité"
git push -u origin demo/securite
gh pr create --base main --title "Démonstration de sécurité" --body "Scénario volontairement vulnérable."
```

Attendre la fin d’**Analyse de sécurité** dans Actions. L’échec est attendu ; vérifier le résumé et l’artifact JSON.

## 4. Lancer la revue IA

Remplacer `1` par le numéro de la PR :

```bash
gh workflow run ai-review.yml --ref main -f pr_number=1
```

Dans Actions, suivre **Revue de sécurité IA**, puis lire le commentaire de la PR.
Relancer la revue pour vérifier la mise à jour du même commentaire, sans doublon.

## 5. Corriger et vérifier

Sur la branche de la PR :

```bash
sed -i 's|0\.0\.0\.0/0|10.0.0.0/24|; s|Volontairement vulnérable|Accès limité au réseau privé|' demo/terraform/main.tf
sed -i '1c\# Image corrigée pour la démonstration, sans déploiement.' demo/Dockerfile
sed -i 's|^FROM .*|FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f|' demo/Dockerfile
git add demo/terraform/main.tf demo/Dockerfile
git commit -m "Restreint SSH et met à jour l’image"
git push
```

Attendre le nouveau scan, puis relancer la revue avec le même numéro de PR.
Sans constat, le commentaire l’indique et Gemini n’est pas appelé.

## Essai local sans clé

```bash
.venv/bin/python -m scripts.gemini_review --simuler
.venv/bin/python -m scripts.github_comment apercu
```

L’aperçu est dans `reports/comment-preview.md`. Il est marqué comme simulation et ne peut pas être publié.
Pour un appel réel local, exporter `GEMINI_API_KEY`, puis lancer la même commande sans `--simuler`.

## Vidéo de 60 à 90 secondes

Montrer : SSH ouvert → PR → scans et rapports → commentaire Gemini → correction → nouveau scan.
Utiliser uniquement les résultats réellement obtenus. Les scans locaux du 1er novembre donnaient un constat par scanner avant correction, puis zéro après. Le parcours GitHub/Gemini reste à vérifier ; ne pas présenter la simulation comme un appel réel.
