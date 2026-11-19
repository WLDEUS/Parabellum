# Sécurité de la chaîne d'approvisionnement (dépôt, CI, signatures)

Parabellum installe un daemon root qui se met à jour seul. Le vrai risque n'est pas seulement un
malware sur le Mac : c'est **un dépôt ou une CI compromis** qui publierait une base ou un `.pkg`
signés. Ce document décrit les barrières en place et ce qu'il reste à faire une fois.

## Ce qui fait foi sur le Mac

| Ce que le daemon accepte | Vérifié par | Clé / ancre |
|---|---|---|
| Base de menaces (nightly) | minisign avant tout dépaquetage, puis chaque empreinte | `keys/parabellum-db.pub` (compilée dans le daemon) |
| Mise à jour de Parabellum (`.pkg`, installée en root) | minisign | `keys/parabellum-release.pub` si présente, sinon la clé DB (transition) |
| sing-box | SHA-256 épinglé dans la base signée, **URL limitée** à `https://github.com/SagerNet/sing-box/releases/download/` | base signée |
| ClamAV, osquery, LuLu, BlockBlock… | Team ID Apple | Apple |

## Deux clés, deux niveaux de confiance

- **Clé DB** (`MINISIGN_SECRET_KEY`) : signe la base. Elle n'est jamais présente dans le job qui télécharge
  les flux et décompresse les échantillons de malware.
- **Clé release** (`MINISIGN_RELEASE_SECRET_KEY`) : signe uniquement les `.pkg`. Même volée, la clé DB ne
  permet plus de faire installer un programme en root.

Mise en place (une fois, sur le Mac) : `make release-key && git push`, puis `make pkg && make install` pour
que le daemon installé connaisse la nouvelle clé. Les mises à jour automatiques suivantes passent seules.

## Workflows GitHub : le code non fiable n'a jamais de secret ni d'écriture

| Workflow | Job qui exécute du code tiers / des données hostiles | Job qui signe / publie |
|---|---|---|
| `nightly-db.yml` | `build-db` : jeton lecture seule, sans clé (flux, 7-Zip sur échantillons, YARA, ZBT) | `sign-publish` : vérifie la liste exacte des fichiers, signe, publie ; n'exécute aucun code du pipeline |
| `release.yml` | `build` (macOS) : lecture seule, **sans cache** (pas d'empoisonnement de cache dans un `.pkg` signé), `--locked` | `sign-publish` (Linux) : reçoit le `.pkg`, signe avec la clé release, publie |
| `ml-train.yml`, `ml-domains.yml` | `train` : lecture seule (échantillons de malware, pb-features) | `publish` : vérifie qu'il n'y a que des fichiers ordinaires, envoie les modèles |
| `ci.yml` | `macos`, `rust-linux`, `python` : lecture seule | `ci-logs` : pousse seulement les fichiers `.log` sur la branche `ci-logs` |

Pourquoi séparer les jobs : dans un même job, n'importe quel code exécuté plus tôt (script de build d'une
dépendance, échantillon qui exploite 7-Zip) peut écrire `BASH_ENV` ou `PATH` dans `$GITHUB_ENV` et
s'exécuter dans les étapes suivantes, y compris celle qui détient la clé ou le jeton en écriture.

## Contrôles automatiques (`supply-chain.yml`, à chaque push, PR et chaque lundi)

- `scripts/check_repo_hygiene.py` : aucun exécutable, archive, DMG, échantillon ou secret suivi par git
  (liste d'exceptions minuscule) ; chaque action épinglée sur un SHA complet ; pas de
  `pull_request_target` / `workflow_run` ; aucune expression `${{ github.event… }}` / `inputs` injectée dans
  un script shell ; pas de fichier de plus de 2 Mo.
- `cargo deny` (`deny.toml`) : avis RustSec, crates.io uniquement (pas de dépendance git), pas de crate
  retirée. Les deux exceptions sont justifiées dans le fichier.
- Python : les trois fichiers `*.lock` s'installent avec `pip --require-hashes`
  (régénération : `make -C pipeline lock`).
- `.gitignore` refuse `.cache/`, archives, DMG, wheels, bibliothèques : un `git add -A` ne peut plus
  embarquer un échantillon ou un outil téléchargé.

## Réglages GitHub (une fois) : `make protect-repo`

`scripts/protect-repo.sh` (gh authentifié en admin) applique :
- `main` : pas de suppression ni de force-push, passage obligatoire par une PR dont les contrôles sont verts
  (Rust, Python, macOS, hygiène, cargo-deny) ;
- tags `v*` : création, déplacement et suppression réservés aux admins (un tag déclenche la release signée) ;
- jeton Actions par défaut en lecture seule, les workflows ne peuvent pas approuver de PR, exécutions des PR
  de forks soumises à approbation ;
- alertes et correctifs Dependabot, secret scanning + protection au push.

## Risques résiduels (assumés)

- Une dépendance compromise au moment du build peut toujours piéger un binaire *avant* signature : les
  barrières ci-dessus empêchent le vol des clés et l'écriture dans le dépôt, pas un build piégé ponctuel.
  Parades : `--locked`, `cargo deny` hebdo, peu de dépendances.
- Le certificat de signature de code macOS (p12, pour garder l'accès complet au disque entre deux versions)
  est importé dans le job de build : il n'est pas l'ancre de confiance des mises à jour (minisign l'est).
- Les modèles ML publiés ne sont pas signés à part : ils n'entrent sur le Mac qu'à travers la base signée
  et le ML n'est jamais seul juge.
