# Parabellum : build et installation

Cible : un Mac Apple Silicon sous macOS 14 ou plus récent. Le paquet n'est pas signé par Apple (pas de compte
développeur payant) : les binaires sont signés **ad hoc** avec le hardened runtime.

## 1. Prérequis

| Outil | Requis | Installation | Vérification |
|---|---|---|---|
| macOS 14+, Apple Silicon, terminal natif (pas Rosetta) | oui | | `sw_vers`, `uname -m` → `arm64` |
| Outils Xcode (`codesign`, `pkgbuild`, `productbuild`, `swift`) | oui | `xcode-select --install` | `xcode-select -p` |
| Xcode complet | pour `swift test` | App Store | XCTest absent des outils seuls |
| Rust (rustup) ≥ `rust-version` de `Cargo.toml` + cible `aarch64-apple-darwin` | oui | <https://rustup.rs>, puis `rustup target add aarch64-apple-darwin` (fait par `make build`) | `rustc --version` |
| minisign | non | `brew install minisign` | vérifier une base à la main |
| gh (GitHub CLI) | non | `brew install gh`, `gh auth login` | secrets, artefacts CI |
| shellcheck | non | `brew install shellcheck` | utilisé par `make lint` |

`make dev-check` vérifie tout et indique ce qui manque.

## 2. Clés et certificat de signature

La base de menaces est signée par la CI (minisign) et vérifiée par le client avec une clé publique **compilée dans
`parabellumd`**. À faire une fois :

1. `make keys` (lance `scripts/setup-signing-keys.sh`).
2. Committer la clé publique `keys/parabellum-db.pub`. La clé secrète ne doit jamais être commitée (`*.key` est ignoré).
3. Mettre la clé secrète dans le secret GitHub `MINISIGN_SECRET_KEY` (§ 8).

Base de menaces : clés minisign ci-dessus. Binaires : certificat de signature de code ci-dessous.

Sans clé publique, `make pkg` refuse de construire (`ALLOW_MISSING_PUBKEY=1` pour forcer : le client refusera alors
toute base). Changer de clé impose de réinstaller un `.pkg` construit avec la nouvelle.

### Certificat de signature de code (recommandé, une fois)

Pourquoi : macOS (TCC) enregistre l'accès complet au disque de `parabellumd` avec son **exigence désignée**
(designated requirement). Signé ad hoc, c'est l'empreinte (cdhash) d'un build précis : chaque mise à jour perd
l'autorisation. Signé par un même certificat, l'exigence devient `identifier "com.wldeus.parabellum.daemon" and
certificate root = H"<empreinte du certificat>"` : identique d'un build à l'autre, l'autorisation est conservée.
Un certificat auto-signé suffit (gratuit, aucun compte Apple).

1. Sur le Mac, sans sudo : `make codesign-cert` (lance `scripts/setup-codesign-cert.sh`).
2. Le script crée « Parabellum Local Signing » (usage limité à la signature de code, 10 ans), l'importe dans le
   trousseau de session et l'approuve pour la signature de code : **macOS demande votre mot de passe** (fenêtre
   « réglages de confiance »). À la signature de test, si macOS demande si `codesign` peut utiliser la clé :
   **Toujours autoriser**.
3. Il exporte `~/.parabellum/parabellum-codesign.p12` et son mot de passe (droits 0600), puis, si `gh` est connecté,
   crée les secrets `MACOS_SIGN_P12` et `MACOS_SIGN_P12_PASSWORD` (§ 8) : la CI signe alors avec le même certificat.
4. Sauvegardez `~/.parabellum/` hors du dépôt. Relancer le script ne recrée rien ; `--force` crée un nouveau
   certificat (accès complet au disque à redonner une fois).

`make app` / `make pkg` utilisent ce certificat s'il est dans le trousseau (ou `PARABELLUM_SIGN_IDENTITY`), sinon
signent ad hoc avec un avertissement. `parabellumd` garde la seule exception du hardened runtime nécessaire à YARA-X.

## 3. Construire localement

```sh
make pkg          # cargo build --release (arm64) + swift build + .app + .pkg
```

| Étape | Commande seule | Résultat |
|---|---|---|
| Rust | `make build-rust` | `target/aarch64-apple-darwin/release/{parabellumd,parabellum}` |
| Swift | `make build-swift` | `app/.build/arm64-apple-macosx/release/Parabellum` |
| App | `make app` | `dist/Parabellum.app` (icône générée, signée ad hoc) |
| Paquet | `make pkg` | `dist/Parabellum-<version>.pkg` + `.sha256` |

La version vient de `[workspace.package] version` dans `Cargo.toml` ; le numéro de build, du nombre de commits
(ou de la date UTC sur un clone partiel). `scripts/build-pkg.sh --skip-build` réutilise les binaires déjà compilés.

Le paquet installe :

| Chemin | Contenu |
|---|---|
| `/Applications/Parabellum.app` | App de barre de menus |
| `/Library/Application Support/Parabellum/bin/` | `parabellumd`, `parabellum`, `uninstall.sh`, `restore-dns.sh` |
| `/Library/LaunchDaemons/com.wldeus.parabellum.daemon.plist` | Daemon root, relancé s'il s'arrête |
| `/Library/LaunchAgents/com.wldeus.parabellum.ui.plist` | App lancée à chaque session (relancée après un crash, pas après « Quitter ») |
| `/usr/local/bin/parabellum` | Lien vers la CLI |
| `/Library/Logs/Parabellum/` | Journaux |

## 4. Construire en CI et récupérer le paquet

Les workflows sont dans `.github/workflows/` : base nocturne (`nightly-db.yml`), modèle ML (`ml-train.yml`),
paquet de l'app (`release.yml`, sur un runner macOS arm64). Pour récupérer le `.pkg` :

```sh
# depuis la dernière release
gh release download --repo WLDEUS/Parabellum --pattern 'Parabellum-*.pkg' --dir ~/Downloads
# ou depuis les artefacts d'une exécution (onglet Actions)
gh run list --repo WLDEUS/Parabellum --workflow release.yml
gh run download <run-id> --repo WLDEUS/Parabellum --dir ~/Downloads
shasum -a 256 ~/Downloads/Parabellum-*.pkg   # comparer avec le .sha256 publié
```

Un fichier téléchargé avec `gh` ou `curl` n'a pas l'attribut de quarantaine : Gatekeeper ne bloque pas.

## 5. Installer

| Méthode | Commande |
|---|---|
| Terminal (recommandé) | `sudo installer -pkg ~/Downloads/Parabellum-<version>.pkg -target /` |
| Depuis le dépôt | `make install` |
| Double-clic | Ouvre Installer.app |

Paquet téléchargé avec un navigateur, puis double-cliqué : macOS refuse de l'ouvrir (développeur non identifié).

1. Cliquez sur **OK** (ou **Terminé**) dans l'alerte.
2. Ouvrez **Réglages Système > Confidentialité et sécurité**, descendez à la section **Sécurité**.
3. Cliquez sur **Ouvrir quand même** à côté du nom du paquet, puis confirmez avec votre mot de passe.

L'installeur refuse les Mac Intel et les macOS antérieurs à 14. Il arrête l'ancienne version, installe, démarre le
daemon puis l'app. macOS peut afficher « Éléments d'arrière-plan ajoutés » : laissez-les autorisés.
Journal d'installation : `grep parabellum /var/log/install.log`.

## 6. Accès complet au disque

Indispensable : sans lui, `eslogger` (surveillance temps réel) ne démarre pas et une partie de vos dossiers reste
illisible. L'app affiche alors « Protection dégradée ».

1. Ouvrez **Réglages Système > Confidentialité et sécurité > Accès complet au disque**.
2. Cliquez sur **+** (mot de passe demandé).
3. Tapez **Cmd + Maj + G** et collez : `/Library/Application Support/Parabellum/bin/parabellumd`
4. Cliquez sur **Ouvrir**, vérifiez que l'interrupteur **parabellumd** est activé.
5. Redémarrez le daemon : `sudo launchctl kickstart -k system/com.wldeus.parabellum.daemon`
6. Vérifiez : `parabellum status` doit indiquer l'accès complet au disque.

Avec le certificat « Parabellum Local Signing » (§ 2), l'autorisation est conservée lors des mises à jour.
Avec un build signé **ad hoc** (avertissement de `make pkg`, ou CI sans les secrets de signature), elle est perdue
à chaque mise à jour : sélectionnez `parabellumd`, retirez-le (**−**) et rajoutez-le (étapes 2 à 5). Même chose
une seule fois lors du passage de l'ad hoc au certificat, ou après `setup-codesign-cert.sh --force`.

## 7. Premier démarrage

| Élément | Qui s'en charge | Action de votre part |
|---|---|---|
| Base de menaces | Daemon, au démarrage puis chaque jour (3 h par défaut) | Aucune |
| ClamAV, osquery, dnscrypt-proxy | Daemon : téléchargés depuis les releases officielles, signature vérifiée, installés, mis à jour | Aucune (quelques minutes, réseau requis) |
| LuLu (pare-feu sortant), BlockBlock (persistance) | À la demande : app > Composants > Installer | Approuver l'extension réseau (LuLu) et l'accès complet au disque (BlockBlock) |
| uBlock Origin Lite Chrome | Vous | [Chrome Web Store](https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh) |
| uBlock Origin Lite Safari | Vous | [App Store](https://apps.apple.com/app/id6745342698), puis Safari > Réglages > Extensions > activer |
| Blocage DNS global | Désactivé par défaut | L'activer dans l'app **après** le retrait de Kaspersky (§ 9) |
| Notifications | App | Accepter la demande d'autorisation |

L'app vérifie l'état de chaque élément (menu **Composants** et **Pubs et trackers**).

## 8. Secrets GitHub

À créer dans **Settings > Secrets and variables > Actions > New repository secret**, ou avec `gh secret set` :

| Secret | Contenu | Obtention |
|---|---|---|
| `MINISIGN_SECRET_KEY` | Clé secrète minisign de la base | Produite par `make keys` (§ 2) : suivez les instructions affichées, ou `gh secret set MINISIGN_SECRET_KEY < <fichier de clé secrète>` |
| `ABUSECH_AUTH_KEY` | Clé d'API abuse.ch (MalwareBazaar, URLhaus, ThreatFox) | Voir ci-dessous |
| `MACOS_SIGN_P12` | `.p12` du certificat de signature, en base64 | `make codesign-cert` (§ 2) le crée avec `gh` ; à la main : `base64 -i ~/.parabellum/parabellum-codesign.p12 \| gh secret set MACOS_SIGN_P12` |
| `MACOS_SIGN_P12_PASSWORD` | Mot de passe du `.p12` | `gh secret set MACOS_SIGN_P12_PASSWORD < ~/.parabellum/parabellum-codesign.p12.password` |

Sans les deux secrets de signature, la CI signe ad hoc (avertissement dans le job). Les builds de pull request
signent toujours ad hoc : ils ne voient jamais la clé. En CI, `scripts/ci-codesign.sh` importe le certificat dans un
trousseau temporaire, supprimé en fin de job.

Clé abuse.ch (gratuite, usage non commercial) :

1. Ouvrez <https://auth.abuse.ch/> et connectez-vous avec un compte GitHub, Google, LinkedIn ou X.
2. Cliquez sur **Save profile**.
3. Dans la section **Optional**, générez une **Auth-Key** et copiez-la.
4. `gh secret set ABUSECH_AUTH_KEY --repo WLDEUS/Parabellum` puis collez la clé.

Dépôt privé : le daemon a besoin d'un token GitHub en lecture seule (fine-grained, « Contents: read ») dans
`updates.github_token` (réglage de l'app) pour télécharger la base et les mises à jour.

## 9. Transition avec Kaspersky

Le cahier des charges impose de ne pas laisser le Mac sans protection : les deux tournent ensemble le temps de valider
Parabellum.

| Période | Kaspersky | Parabellum | À faire |
|---|---|---|---|
| Jour 0 | Actif | Installé, DNS désactivé | Dans Kaspersky, exclure `/Library/Application Support/Parabellum/` (la base contient des signatures, la quarantaine des fichiers neutralisés) et un dossier de test, par ex. `~/parabellum-test` |
| Jours 1 à 7 | Actif | Actif | Chaque jour : `parabellum status` (base mise à jour automatiquement). Tester dans `~/parabellum-test` : fichier de test [EICAR](https://www.eicar.org/download-anti-malware-testfile/) → détecté et mis en quarantaine ; analyse d'un DMG et d'un PKG ; LaunchAgent de test → alerte de persistance |
| Après validation | Désinstallé | Actif | Désinstaller Kaspersky avec son propre outil de désinstallation, redémarrer, activer le blocage DNS, garder XProtect + LuLu + BlockBlock |

Critères pour retirer Kaspersky (phases 1 et 2 de la roadmap) : base mise à jour 7 jours de suite, EICAR détecté et
mis en quarantaine, scan DMG/PKG correct, protection « active » (pas « dégradée »), aucun faux positif bloquant.

Pendant la cohabitation : deux analyses temps réel coûtent plus de CPU sur les téléchargements, et la protection web
de Kaspersky peut entrer en conflit avec le DNS local : gardez le blocage DNS de Parabellum désactivé jusqu'au retrait.

## 10. Mises à jour

| Quoi | Comment |
|---|---|
| Base de menaces, signatures ClamAV | Automatique, chaque jour |
| ClamAV, osquery, dnscrypt-proxy, LuLu, BlockBlock | Automatique (réglage `updates.auto_update_components`) |
| Parabellum lui-même | Notification d'une nouvelle release ; installer le nouveau `.pkg` (§ 5). Accès complet au disque conservé si le build est signé avec le certificat (§ 2), à refaire sinon (§ 6) |

## 11. Dépannage

| Symptôme | Diagnostic | Correctif |
|---|---|---|
| L'app dit « daemon injoignable » | `sudo launchctl print system/com.wldeus.parabellum.daemon` (state, pid, last exit code) | `sudo launchctl kickstart -k system/com.wldeus.parabellum.daemon` ; lire les journaux |
| Le daemon redémarre en boucle | `tail -n 100 /Library/Logs/Parabellum/parabellumd.stderr.log` et `parabellumd.log` | Selon l'erreur ; vérifier l'espace disque et la présence des binaires |
| « Protection dégradée » après une mise à jour | `parabellum status` ; `codesign -d -r- "/Library/Application Support/Parabellum/bin/parabellumd"` (`cdhash` = ad hoc) | Redonner l'accès complet au disque (§ 6) ; pour ne plus avoir à le faire : `make codesign-cert` + secrets CI (§ 2, § 8) |
| Plus d'accès Internet après activation du DNS | `scutil --dns`, `networksetup -getdnsservers Wi-Fi` | `parabellum dns off` ; secours sans daemon : `sudo "/Library/Application Support/Parabellum/bin/restore-dns.sh"` |
| Base jamais mise à jour | `parabellum status` (version, dernière erreur) | Signature refusée = clé publique du binaire ≠ clé secrète de la CI (§ 2) ; dépôt privé = token manquant (§ 8) |
| Le daemon ou l'app ne démarre pas au login | Réglages Système > Général > Ouverture (éléments d'arrière-plan) | Réactiver les entrées Parabellum |
| L'app n'apparaît pas dans la barre de menus | `launchctl print gui/$(id -u)/com.wldeus.parabellum.ui` | `open -a Parabellum` |
| L'installation échoue | `grep parabellum /var/log/install.log` | Selon le message |

Journaux : `/Library/Logs/Parabellum/` (`parabellumd.log`, `parabellumd.stdout.log`, `parabellumd.stderr.log`).
État complet : `parabellum status` ; aide de la CLI : `parabellum --help`.

## 12. Désinstaller

```sh
sudo "/Library/Application Support/Parabellum/bin/uninstall.sh"            # garde quarantaine, historique, config, journaux
sudo "/Library/Application Support/Parabellum/bin/uninstall.sh" --purge    # efface tout ; quarantaine déplacée
```

Depuis le dépôt : `make uninstall` (ou `make uninstall PURGE=1`).

Ordre suivi par le script :

1. Rend les DNS d'origine (`parabellum dns off`, puis secours depuis `dns/saved-dns.json` pour tout service encore sur le résolveur local).
2. Arrête l'app et le daemon.
3. Supprime l'app, les binaires, les plists, le lien `/usr/local/bin/parabellum`, la base, et oublie le reçu `com.wldeus.parabellum.pkg`.
4. Avec `--purge` : déplace la quarantaine vers `/Users/Shared/Parabellum-quarantine-<date>` (root seulement, jamais supprimée), puis efface données et journaux.

ClamAV, osquery, LuLu et BlockBlock ne sont **pas** supprimés : le script affiche comment les retirer. Retirez aussi
`parabellumd` de la liste « Accès complet au disque ».
