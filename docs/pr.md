# Tester avec une PR

Depuis la racine du dépôt, avec un espace de travail propre et GitHub CLI connecté.
Les workflows et les scripts à tester doivent déjà être sur `main`. Le secret `GEMINI_API_KEY` doit être configuré dans l’environnement `gemini-review`, limité à `main`.

## 1. Créer la PR

```bash
git switch main
git pull --ff-only
git switch -c test/securite
```

Modifie les fichiers à tester uniquement dans `demo/`, puis :

```bash
git add demo/
git commit -m "Teste les contrôles de sécurité"
git push -u origin test/securite
gh pr create --base main --title "Test de sécurité" --body "Vérification Checkov, Trivy et revue IA."
```

## 2. Vérifier les scans et lancer la revue IA

Checkov et Trivy démarrent automatiquement. Une fois le contrôle apparu dans la PR :

```bash
gh pr checks --watch
```

Un échec est attendu si des problèmes bloquants sont détectés. Après la fin du scan, remplace `1` par le numéro de ta PR :

```bash
gh workflow run ai-review.yml --ref main -f pr_number=1
gh pr view --web
```

Attends la fin de **Revue de sécurité IA** dans Actions, puis consulte le commentaire de la PR. Les rapports complets sont dans les archives des workflows.

## 3. Vérifier après correction

Corrige les fichiers dans `demo/` sur la même branche, puis :

```bash
git add demo/
git commit -m "Corrige les problèmes de sécurité"
git push
```

Attends que le nouveau scan apparaisse dans la PR, puis :

```bash
gh pr checks --watch
gh workflow run ai-review.yml --ref main -f pr_number=1
gh pr view --web
```

Utilise le même numéro de PR. Après la fin des workflows, le contrôle doit réussir si les problèmes bloquants sont corrigés et le commentaire est mis à jour. Sans constat, Gemini n’est pas appelé.
