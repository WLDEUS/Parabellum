# Sécurité de la chaîne d'approvisionnement (dépôt, CI, signatures)

Parabellum installe un daemon root qui se met à jour seul. Le vrai risque n'est pas seulement un
malware sur le Mac : c'est **un dépôt ou une CI compromis** qui publierait une base ou un `.pkg`
signés. Ce document décrit les barrières en place et ce qu'il reste à faire une fois.

## Ce qui fait foi sur le Mac

| Ce que le daemon accepte | Vérifié par | Clé / ancre |
|---|---|---|
| Base de menaces (nightly) | minisign avant tout dépaquetage, puis chaque empreinte | `keys/parabellum-db.pub` (compilée dans le daemon) |
| Mise à jour de Parabellum (`.pkg`, installée en root) | minisign, commentaire de confiance `Parabellum <version> (<commit>)` | `keys/parabellum-release.pub` (la CI refuse désormais de publier sans elle) |
| sing-box | SHA-256 épinglé dans la base signée, **URL limitée** à `https://github.com/SagerNet/sing-box/releases/download/` | base signée |
| Ollama (agent courrier) | SHA-256 épinglé (`components/ollama.json`, URL limitée aux releases `ollama/ollama`), puis `codesign --strict` Team ID `3MU9H2V9Y9` + Gatekeeper sur `ollama` et `llama-server` | base signée + Apple |
| ClamAV, osquery, LuLu, BlockBlock… | Team ID Apple | Apple |

## Deux clés minisign, deux niveaux de confiance, toujours chiffrées

- **Clé DB** : signe la base, l'état du pipeline et les modèles ML promus (commentaire
  `parabellum-ml <run> <fichier>`, distinct de `parabellum-db <version>`). Jamais présente dans un job qui
  télécharge des flux, décompresse des échantillons ou compile du code tiers.
- **Clé release** : signe uniquement les `.pkg`. Même volée, la clé DB ne permet pas de faire installer un
  programme en root.

Les deux clés sont **protégées par mot de passe** (scrypt, audit SC-2) : le fichier de clé et son mot de
passe sont deux secrets distincts de l'environnement GitHub, passés à minisign sur l'entrée standard par
`scripts/ci-minisign.sh`, qui écrit la clé dans un fichier temporaire `0600` effacé même en cas d'échec,
puis revérifie la signature et son commentaire avec la clé publique commitée. Aucune copie en clair ne reste
sur le Mac : `scripts/secure-local-keys.sh` (voir plus bas).

## Environnements GitHub : un secret n'atteint que le job qui en a besoin (audit SC-1)

Aucun secret de signature n'est au niveau du dépôt. Ils vivent dans des environnements que seuls certains
jobs déclarent (`environment:`), avec une règle de déploiement :

| Environnement | Règle | Secrets | Jobs |
|---|---|---|---|
| `db-signing` | branche `main` uniquement | `MINISIGN_SECRET_KEY`, `MINISIGN_KEY_PASSWORD` | `nightly-db.yml` / `sign-publish`, `ml-train.yml` / `publish`, `ml-domains.yml` / `publish` |
| `release` | tags `v*` uniquement + relecteur obligatoire (le propriétaire) | `MINISIGN_RELEASE_SECRET_KEY`, `MINISIGN_RELEASE_KEY_PASSWORD` | `release.yml` / `sign-publish` |
| `codesign` | tags `v*` uniquement | `MACOS_SIGN_P12`, `MACOS_SIGN_P12_PASSWORD` | `release.yml` / `package` |

Un workflow lancé depuis une autre branche, une PR ou un job sans `environment:` ne reçoit donc rien, même
si quelqu'un y ajoute `${{ secrets.… }}`. Seul `ABUSECH_AUTH_KEY` (clé d'API en lecture) reste au niveau du
dépôt. Dans chaque job, la clé n'est donnée qu'à l'étape qui signe (`env:` d'étape), pas au job entier.

## Workflows : le code non fiable n'a jamais de secret ni d'écriture

| Workflow | Job qui exécute du code tiers / des données hostiles | Contrôle indépendant | Job qui signe / publie |
|---|---|---|---|
| `nightly-db.yml` | `build-db` : jeton lecture seule, sans clé (flux, 7-Zip sur échantillons, YARA, ZBT) | `verify-db` : runner neuf, lecture seule, sans secret (voir plus bas) | `sign-publish` (`db-signing`) : liste exacte des fichiers, **mêmes octets que ceux vérifiés**, signe, publie ; n'exécute aucun code du pipeline |
| `release.yml` | `build` : `cargo build --locked` du daemon et de la CLI, lecture seule, **sans aucun secret ni cache** | — | `package` (`codesign`) : app Swift (sans dépendance externe) + `.pkg` à partir des binaires reçus, certificat importé **non exportable** ; `sign-publish` (`release`) : signe le `.pkg`, publie |
| `ml-train.yml`, `ml-domains.yml` | `train` : lecture seule (échantillons de malware, pb-features) | `build-db` puis `verify-db` revérifient les signatures | `publish` (`db-signing`) : fichiers ordinaires seulement, **signe chaque fichier promu**, envoie modèle + `.minisig` |
| `ci.yml` | `macos`, `rust-linux`, `python` : lecture seule, `.pkg` de CI signé **ad hoc** (plus de certificat dans ce job) | — | `ci-logs` : pousse seulement les fichiers `.log` sur la branche `ci-logs` |

Pourquoi séparer les jobs : dans un même job, n'importe quel code exécuté plus tôt (script de build d'une
dépendance, échantillon qui exploite 7-Zip) peut écrire `BASH_ENV` ou `PATH` dans `$GITHUB_ENV` et
s'exécuter dans les étapes suivantes, y compris celle qui détient la clé ou le jeton en écriture. C'est
aussi pourquoi le certificat de signature de code n'est plus importé dans un job qui compile des crates
(audit SC-8) : un `build.rs` piégé aurait pu signer n'importe quel binaire avec l'identité qui porte l'accès
complet au disque de `parabellumd`.

### `verify-db` : ce que la base doit prouver avant d'être signée (audit SC-4)

`build-db` est supposé compromissible. `pipeline/verify_bundle.py` relit la base dans un autre job et la
compare à des références que `build-db` ne peut pas toucher (base précédente dont la signature est
revérifiée, dépôt, amont) :

- fichiers maintenus à la main (`local_file` de `sources.toml` : Team ID de confiance, liste blanche DNS,
  pack osquery) identiques octet pour octet au dépôt ;
- `zbt/zero-breach-toolkit.py` (Python exécuté par le daemon) : la copie de la veille, ou un script listé
  dans le `SHA256SUMS` de la release amont signé par la clé PGP épinglée ;
- chaque fichier `ml/` : la copie de la veille ou un asset ML signé (`scripts/fetch-ml-models.sh`) ;
- épingles `components/*.json` modifiées : URL de la release officielle, empreinte calculée par GitHub
  identique, et pour sing-box attestation de provenance valide (`gh attestation verify`) ;
- `hashes/allow.sha256` (empreintes qui font taire la détection) : croissance bornée (max(5000, 10 %)), et au
  plus 25 empreintes « malware » de la veille passées en liste blanche ; au-delà il faut l'entrée
  `allow_allowlist_growth` du `workflow_dispatch` ;
- comptes recalculés depuis les fichiers (empreintes malware, fichiers YARA, domaines bloqués) : pas de chute
  de plus de moitié sans `allow_shrink` ;
- `manifest.json` interne cohérent avec les fichiers, et identique au `manifest.json` publié à côté.

`verify-db` publie l'empreinte de chaque fichier vérifié ; `sign-publish` refuse de signer si un seul octet
diffère. Limite : le contenu des flux tiers (empreintes, domaines, règles YARA) ne peut pas être revérifié
sans tout reconstruire ; c'est le rôle du garde de cohérence, de la porte anti-faux positifs et de la
quarantaine réversible côté client.

### Modèles ML (audit SC-7)

- `publish` signe chaque fichier promu avec la clé DB, commentaire `parabellum-ml <run id> <fichier>`.
- `build-db` (et `verify-db`) ne gardent un modèle que si **tous** ses fichiers sont signés, que chaque
  commentaire nomme le bon fichier et que tous viennent du même run (pas de mélange d'un ancien modèle signé
  avec une méta plus récente). Sinon le modèle est écarté et celui de la veille est reconduit.
- La porte anti-faux positifs de la base rejoue le modèle Mach-O qui va partir sur le corpus propre :
  au-delà de `ml_max_fp_rate` (0,5 %, `sources.toml`) la base n'est pas publiée. Elle arrête un modèle cassé
  ou hostile qui signale le corpus en masse, pas un modèle ciblé : le ML n'est jamais seul juge et la
  quarantaine reste réversible.

### Caches (audit SC-5)

Un cache GitHub peut être écrit par n'importe quel workflow du dépôt. Seuls les téléchargements du corpus
propre (revérifiés contre leur SHA-256 épinglé à chaque exécution) et l'index des bottles Homebrew (n'accepte
que des URL `ghcr.io/v2/homebrew/core/<formule>/blobs/sha256:<empreinte>`) sont mis en cache ; les
arborescences sont réextraites à chaque fois, donc un cache empoisonné ne peut pas ajouter un fichier à la
liste blanche. Les clés de cache n'ont plus de préfixe générique, et le cache Rust de `nightly-db.yml`
(`pb-features-db`) n'est pas partagé avec celui de `ml-train.yml`, qui traite des échantillons. `release.yml`
n'utilise aucun cache.

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
- alertes et correctifs Dependabot, secret scanning + protection au push ;
- les trois environnements ci-dessus avec leurs règles (le relecteur obligatoire de `release` demande un
  dépôt public ou une offre payante ; sinon l'environnement est créé sans relecteur et le script le signale).

## Clés sur le Mac : `scripts/secure-local-keys.sh`

| Commande | Effet |
|---|---|
| `status` | inventaire de `~/.parabellum` (clés chiffrées ou non, copies `.bak`, `.p12`, fichiers de mot de passe en clair) et emplacement des secrets GitHub ; n'affiche jamais un secret |
| `encrypt` | `minisign -C` sur chaque clé sans mot de passe : la clé publique ne change pas, aucune recompilation du client |
| `migrate` | vérifie chaque clé contre la clé publique commitée, l'envoie avec son mot de passe dans son environnement, puis supprime la copie au niveau du dépôt |
| `purge` | après sauvegarde dans le gestionnaire de mots de passe : supprime clés, `.bak`, `.p12` et mots de passe locaux ; refusé tant qu'une clé publique n'est pas commitée ou qu'un environnement n'a pas son secret |

`setup-signing-keys.sh`, `setup-release-key.sh` et `setup-codesign-cert.sh` créent désormais des clés
protégées par un mot de passe tapé (jamais écrit sur le disque), ne gardent plus de `.bak` et envoient les
secrets directement dans les environnements. Le certificat de signature de code est importé dans le trousseau
de session comme **non exportable** et sans application pré-autorisée : macOS demande avant que `codesign`
s'en serve (répondre « Autoriser », pas « Toujours autoriser »), pour qu'aucun autre processus ne puisse
signer en silence un binaire qui hériterait de l'accès complet au disque.

## Installateur (audit IPC-6)

Le `postinstall` (root) ne crée `/usr/local/bin/parabellum` que si `/usr/local` et `/usr/local/bin` sont de
vrais dossiers appartenant à root et non modifiables par le groupe ou les autres ; sinon (Homebrew Intel,
lien symbolique) le lien est sauté et journalisé, et un fichier existant qui n'est pas un lien n'est jamais
écrasé.

## Risques résiduels (assumés)

- Une dépendance compromise au moment du build peut toujours piéger un binaire *avant* signature : les
  barrières ci-dessus empêchent le vol des clés et l'écriture dans le dépôt, pas un build piégé ponctuel.
  Parades : `--locked`, `cargo deny` hebdo, peu de dépendances, aucun cache pour les releases.
- Le job `package` signe des binaires produits par `build` (qui compile du code tiers) : un build piégé
  serait signé. Le certificat, lui, ne peut plus être volé ni utilisé par ce code.
- Les indicateurs ZBT (`zbt/indicators/*`) sont produits en CI par le script vérifié et ne peuvent pas être
  revérifiés indépendamment : ce sont des données, lues par un script dont l'origine est prouvée.
- `pipeline-state.tar.gz` (état reporté d'une nuit à l'autre) est signé mais pas revérifié par `verify-db` :
  il n'atteint jamais le Mac, et chaque base construite à partir de lui repasse par `verify-db`.
- Le relecteur obligatoire de l'environnement `release` dépend de l'offre GitHub (voir plus haut).
