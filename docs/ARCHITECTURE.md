# Parabellum — architecture

> Antivirus perso pour macOS 14+ sur Apple Silicon. On ne code pas de moteur de détection : on orchestre des
> briques open source éprouvées et on écrit la colle, l'interface et le pipeline de mise à jour de la base.

## Vue d'ensemble

```
                    ┌──────────────────────── Mac (arm64) ────────────────────────┐
                    │                                                             │
 GitHub Actions     │  Parabellum.app (SwiftUI, LaunchAgent)                      │
 ───────────────    │    barre de menus + fenêtre + notifications                 │
 nightly-db.yml ──┐ │        │  JSON-lines sur /var/run/parabellum.sock           │
 ml-train.yml   ──┤ │        ▼                                                    │
 release.yml    ──┤ │  parabellumd (Rust, LaunchDaemon root)                      │
                  │ │    ├─ pb-monitor : FSEvents, eslogger (ES, observation),    │
   bundle signé   │ │    │               persistance, périphériques, osquery      │
   minisign  ─────┼─┼──► ├─ pb-engine  : hash DB, YARA-X, ClamAV (clamscan),      │
   (db-latest)    │ │    │               DMG/PKG/ZIP, signature Apple, quarantaine│
                  │ │    ├─ pb-ml      : features Mach-O + arbres LightGBM        │
   releases       │ │    ├─ pb-updater : base signée + rollback, freshclam,       │
   tierces ───────┼─┼──► │               ClamAV/osquery/dnscrypt/LuLu/BlockBlock  │
   (pkg signés)   │ │    ├─ pb-dns     : dnscrypt-proxy + listes fusionnées       │
                  │ │    └─ SQLite     : alertes, historique, baseline, rapports  │
                  │ │                                                             │
                  │ │  Navigateurs : uBlock Origin Lite (Chrome Web Store, App    │
                  │ │  Store Safari), état vérifié par le daemon                  │
                  └─┴─────────────────────────────────────────────────────────────┘
```

## Crates et dossiers

| Chemin | Rôle | Langage |
|---|---|---|
| `crates/pb-core` | Contrat partagé : modèle, protocole IPC, config, arborescence disque, manifeste de base | Rust |
| `crates/pb-engine` | Analyse de fichiers, score, cache, quarantaine réversible | Rust |
| `crates/pb-ml` | Extraction de features Mach-O, inférence d'arbres (modèle LightGBM exporté en JSON), binaire `pb-features` | Rust |
| `crates/pb-monitor` | Surveillance temps réel, persistance, périphériques, osquery | Rust |
| `crates/pb-updater` | MAJ de la base (minisign, bascule atomique, rollback), freshclam, gestion des composants tiers, auto-MAJ de l'app | Rust |
| `crates/pb-dns` | Blocage DNS global (dnscrypt-proxy), bascule sûre des DNS système | Rust |
| `crates/pb-daemon` | `parabellumd` : orchestration, serveur IPC, SQLite, planificateur | Rust |
| `crates/pb-cli` | `parabellum` : client en ligne de commande | Rust |
| `app/` | App SwiftUI (barre de menus + fenêtre), paquet SwiftPM | Swift |
| `pipeline/` | Construction nocturne de la base (flux abuse.ch, listes DNS, règles YARA, tests FP/détection) | Python |
| `ml/` | Entraînement hebdo du classifieur Mach-O | Python |
| `rules/` | Règles YARA maison (familles macOS) | YARA |
| `installer/`, `scripts/`, `Makefile` | `.app`, `.pkg`, signature ad hoc, installation/désinstallation | Shell |
| `.github/workflows/` | CI, release, base nocturne, entraînement ML | YAML |

## Décisions clés

- **Rust partout où on lit des données non fiables** (fichiers, archives, plists, flux réseau). Swift seulement pour l'UI.
- **Pas de `clamd`** (≈ 1 Go de RAM résident) : `clamscan` par lots pour les analyses à la demande, volumes et
  planifiées. Le temps réel passe par hash DB + YARA-X + ML (< 200 ms par fichier de moins de 10 Mo).
- **Pas d'entitlement Endpoint Security** (compte gratuit) : `eslogger` (outil Apple, observation seule) +
  FSEvents. On détecte et on met en quarantaine juste après, sans bloquer avant l'exécution.
- **Composants tiers installés depuis leurs releases officielles**, signature vérifiée (Team ID Apple ou minisign)
  avant toute installation, mis à jour automatiquement par le daemon.
- **Pubs** : uBlock Origin Lite des stores (mis à jour par les stores) + blocage DNS maison. Pas d'extension maison :
  sans compte développeur payant, Safari exige de réactiver « Allow unsigned extensions » à chaque lancement.
- **Base signée** (minisign, Ed25519), bascule atomique par lien symbolique, version précédente gardée pour le rollback.
- **ML jamais seul juge** : le score ML rend un fichier « suspect », jamais « malveillant », et ne met rien en quarantaine.
- **Quarantaine réversible** : fichier neutralisé (XOR) + métadonnées, restauration exacte (chemin, droits, propriétaire).
  Aucune suppression sans action explicite.
- **DNS en mode fail-open** : si dnscrypt-proxy tombe, le daemon restaure les DNS d'origine pour ne jamais couper Internet.

Voir aussi : `crates/pb-core/src/ipc.rs` (protocole), `crates/pb-core/src/db.rs` (format de la base),
`docs/INSTALL.md` (build et installation).
