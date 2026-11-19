# Règles pour les agents qui travaillent dans ce dépôt

Parabellum est un antivirus avec un daemon root qui se met à jour seul : une contamination du dépôt finit
installée en root sur le Mac. Avant de committer :

- Jamais de `git add -A` / `git add .` à l'aveugle : relire `git status` et ajouter les fichiers par nom.
  Aucun binaire, archive, wheel, DMG, échantillon de malware ou fichier téléchargé dans le dépôt.
  `python3 scripts/check_repo_hygiene.py` doit passer.
- Les échantillons de malware ne vivent que dans des dossiers temporaires, ne sont jamais exécutés et ne
  quittent jamais la CI ou une VM isolée.
- Aucun secret (clé minisign, jeton, p12) dans un fichier suivi, un log ou un message de commit.
- Workflows : actions épinglées sur un SHA complet, permissions minimales par job, jamais de clé ni de
  jeton en écriture dans un job qui compile du code tiers ou traite des données hostiles, jamais
  d'expression `${{ … }}` contrôlable dans un `run:` (passer par `env:`). Voir docs/SECURITY-SUPPLY-CHAIN.md.
- Dépendances : `Cargo.lock` et les `*.lock` Python sont la vérité ; toute nouvelle dépendance passe
  `cargo deny check` et `make -C pipeline lock`.
- Ne jamais affaiblir un contrôle (hygiène, cargo-deny, signature, vérification minisign) pour faire
  passer la CI : corriger la cause.
- Nom public de l'auteur : « Deus ». Pas de nom réel dans le dépôt ni dans les commits.
