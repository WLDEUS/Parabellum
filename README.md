# Parabellum

Antivirus personnel et open source pour **macOS 14+ sur Apple Silicon**. Un seul Mac, usage perso, aucune distribution.

> On n'écrit pas de moteur de détection : on orchestre des briques open source éprouvées (ClamAV, YARA-X, osquery,
> `eslogger` d'Apple, outils Objective-See, dnscrypt-proxy, uBlock Origin Lite) et on code seulement la colle,
> l'interface et le pipeline de mise à jour de la base.

## Fonctionnalités

| Domaine | Ce que fait Parabellum | Briques |
|---|---|---|
| Analyse à la demande | Fichiers, dossiers, DMG (montés en lecture seule), PKG (dépaquetés), ZIP | Base de hash, YARA-X, ClamAV (`clamscan`) |
| Temps réel | Téléchargements, Bureau, Documents, Applications, programmes lancés : analyse puis quarantaine juste après | FSEvents, `eslogger` (observation seule) |
| Persistance | Nouveaux LaunchAgents/Daemons et éléments de connexion, chasse quotidienne | Moniteur maison, osquery, BlockBlock (option) |
| Périphériques | Scan auto des volumes externes, alerte nouveau clavier (BadUSB), Bluetooth, Thunderbolt, interfaces réseau, nouveaux Wi-Fi | IOKit, `system_profiler` |
| Quarantaine | Fichier neutralisé + métadonnées, restauration exacte, jamais de suppression silencieuse | Rust |
| Base de menaces | Reconstruite chaque nuit en CI, signée minisign, bascule atomique + rollback ; signatures ClamAV via `freshclam` | GitHub Actions, abuse.ch, règles YARA |
| ML | Classifieur Mach-O : peut rendre un fichier « suspect », jamais « malveillant », ne met rien en quarantaine | LightGBM (entraîné en CI) |
| Pubs et trackers | DNS global (malware, pubs, trackers), fail-open ; uBlock Origin Lite dans Chrome et Safari (état vérifié) | dnscrypt-proxy, listes Hagezi/OISD, uBO Lite |
| Suivi | App de barre de menus, notifications, rapport hebdomadaire, CLI `parabellum` | SwiftUI, Rust |
| Maintenance | Composants tiers installés depuis leurs releases officielles, signature vérifiée, mis à jour automatiquement | `pb-updater` |

## Architecture

```
Parabellum.app (SwiftUI, LaunchAgent)  ── JSON lignes sur /var/run/parabellum.sock ──┐
parabellum (CLI)                       ─────────────────────────────────────────────┤
                                                                                     ▼
parabellumd (Rust, LaunchDaemon root) : pb-monitor (FSEvents, eslogger, persistance, périphériques)
                                        pb-engine (hash, YARA-X, ClamAV, DMG/PKG, quarantaine)
                                        pb-ml, pb-updater (base signée, composants), pb-dns, SQLite
GitHub Actions : base nocturne signée (release db-latest), modèle ML hebdo, .pkg de l'app
```

Détails, choix et contrats : [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Build et installation : [docs/INSTALL.md](docs/INSTALL.md).

## Démarrage rapide

1. Vérifier le Mac de dev : `make dev-check` (macOS 14+, arm64, outils Xcode, Rust, Swift).
2. Créer les clés de signature de la base : `make keys` (clé publique dans `keys/`, clé secrète à mettre dans le secret GitHub `MINISIGN_SECRET_KEY`).
3. Créer le certificat de signature stable : `make codesign-cert` (sans lui, l'accès complet au disque est perdu à chaque mise à jour ; crée aussi les secrets CI `MACOS_SIGN_P12*`).
4. Ajouter le secret `ABUSECH_AUTH_KEY` (gratuit, voir [INSTALL.md § 8](docs/INSTALL.md#8-secrets-github)), puis `git push` : la CI publie la base chaque nuit.
5. Construire le paquet : `make pkg` en local, ou télécharger le `.pkg` produit par la CI.
6. Installer : `make install` (ou double-clic sur `dist/Parabellum-<version>.pkg`).
7. Donner l'**Accès complet au disque** à `/Library/Application Support/Parabellum/bin/parabellumd` ([INSTALL.md § 6](docs/INSTALL.md#6-accès-complet-au-disque)).
8. Installer **uBlock Origin Lite** dans Chrome (Chrome Web Store) et Safari (App Store).
9. Vérifier : `parabellum status` (protection « active », base à jour).

## Commandes

| Commande | Effet |
|---|---|
| `make help` | Liste des cibles |
| `make build` / `make app` / `make pkg` | Compile / assemble `dist/Parabellum.app` / construit `dist/Parabellum-<version>.pkg` |
| `make install` / `make uninstall [PURGE=1]` | Installe le paquet / désinstalle (données gardées sauf `PURGE=1`) |
| `make codesign-cert` | Certificat de signature stable (une fois) : l'accès complet au disque survit aux mises à jour |
| `make test` / `make lint` | Tests Rust + Swift / fmt, clippy, shellcheck |
| `make dev-daemon` + `make dev-app` | Daemon sans root sous `.dev-root/` + app branchée dessus |
| `parabellum status` | État de la protection, de la base et des composants |
| `parabellum dns off` | Rend les DNS d'origine (secours : `sudo "/Library/Application Support/Parabellum/bin/restore-dns.sh"`) |

## Couverture du cahier des charges

État visé par la v0.1. Chaque ligne se valide sur le Mac avec le critère de sortie de la phase correspondante.

| ID | Exigence | Priorité | Statut | Comment |
|---|---|---|---|---|
| F1 | Scan à la demande fichier, dossier, DMG/PKG | Must | Couvert | Hash + YARA-X + `clamscan` ; DMG montés en lecture seule, PKG dépaquetés |
| F2 | Scan auto des téléchargements et volumes externes | Must | Couvert | FSEvents sur les dossiers surveillés ; volume monté = scan automatique |
| F3 | MAJ quotidienne auto, vérifiée par signature | Must | Couvert | Bundle nocturne minisign, bascule atomique, rollback ; `freshclam` quotidien |
| F4 | Nouvelles persistances (LaunchAgents/Daemons, login items) | Must | Couvert | Moniteur de persistance + osquery, alerte dans l'app |
| F5 | Quarantaine réversible | Must | Couvert | Restauration exacte (chemin, droits, propriétaire) ; suppression = action explicite |
| F6 | Temps réel Endpoint Security, blocage à l'exécution | Should | Partiel | `eslogger` observe, Parabellum analyse et met en quarantaine juste après. Le blocage avant exécution exige l'entitlement ES (compte développeur payant) |
| F7 | Blocage URLs/domaines malveillants | Should | Couvert (domaines) | URLhaus, ThreatFox, Hagezi TIF dans le DNS local ; pas de filtrage d'URL complète |
| F8 | Rapport hebdo | Could | Couvert | Menaces, MAJ, faux positifs signalés, requêtes DNS bloquées |
| F9 | Score de réputation combiné | Could | Partiel | Signature Apple, Team ID de confiance, notarisation, score ML ; pas de prévalence communautaire (aucun fichier ne quitte le Mac) |
| F10 | Pubs et trackers dans Safari | Must | Délégué | uBlock Origin Lite (App Store), état vérifié. Pas d'extension maison : sans compte payant, Safari la désactive à chaque lancement |
| F11 | Pubs et trackers dans Chrome (MV3) | Must | Délégué | uBlock Origin Lite (Chrome Web Store), mis à jour par le store |
| F12 | Blocage DNS global | Should | Couvert | dnscrypt-proxy + listes fusionnées ; désactivé par défaut ; DNS d'origine rendus si le résolveur tombe |
| F13 | Pubs YouTube (best-effort) | Should | Délégué | Règles YouTube de uBO Lite ; le DNS seul ne suffit pas (mêmes domaines que les vidéos) |

## Sécurité et vie privée

- Aucun fichier ne quitte le Mac. Recherche de hash VirusTotal en option (opt-in), jamais le fichier.
- Binaires signés avec hardened runtime, par un certificat local auto-signé (`make codesign-cert`) ou ad hoc ; seule exception : mémoire exécutable pour YARA-X dans `parabellumd`.
- Base de menaces et composants tiers vérifiés par signature avant usage.
- Le daemon tourne en root : appels d'outils système par chemin absolu, entrées bornées, socket réservé au groupe admin.

## Licence

MIT (voir `Cargo.toml`). Les composants tiers gardent leur licence (ClamAV GPL-2.0, osquery Apache-2.0/GPL-2.0, dnscrypt-proxy ISC, LuLu et uBlock Origin Lite GPL-3.0, autres outils Objective-See : voir leur dépôt) et les listes de blocage leurs conditions d'usage : à relire avant toute diffusion.
