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
| `crates/pb-vpn` | VPN (sing-box ou VPN de macOS), kill switch pf, tests de fuite, garde réseau (ARP spoofing, faux point d'accès) | Rust |
| `crates/pb-privacy` | Demandes RGPD aux courtiers (courriers, délais, relances, plainte CNIL), fuites, Pwned Passwords, alias, métadonnées | Rust |
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
- **Pas de `clamd`** (≈ 1 Go de RAM résident) : `clamscan` par lots pour les analyses à la demande et des volumes.
  Le temps réel passe par hash DB + YARA-X + ML (< 200 ms par fichier de moins de 10 Mo).
- **Parcours et threads** (`crates/pb-engine/src/walk.rs`) : chaque objet n'est vu qu'une fois (racines
  dédoublonnées par `st_dev`+`st_ino` : même dossier deux fois, `/tmp` et `/private/tmp`, racine incluse dans une
  autre, fichier racine rencontré par le parcours, liens suivis qui reviennent dans l'arbre). Un thread parcourt,
  `scan.threads` threads analysent (0 = auto : la moitié des cœurs, 6 max), à la QoS de l'appelant ; ClamAV reste
  un seul `clamscan` à la fois et les fichiers lourds (≥ 8 Mo, DMG, PKG, archives) un à la fois.
- **Analyse complète** (`crates/pb-daemon/src/fullscan.rs`) : racines = dossiers de premier niveau de `/` sauf
  `/System` (volume scellé, signé par Apple, et qui contient `/System/Volumes/Data`, soit `/Users` une 2e fois),
  `/Volumes`, `/dev`, `/cores` et les entrées cachées ; le parcours n'entre que dans les dossiers des volumes du disque
  de démarrage (`st_dev`), donc ni devfs, ni swap, ni partages réseau, ni images montées dans un dossier perso ; les
  fichiers iCloud non téléchargés (`SF_DATALESS`) sont sautés. Sans ClamAV par défaut (`clamscan` recharge sa base
  tous les 256 fichiers : des heures à des jours sur un disque entier). Un emplacement à part dans la file des
  analyses : elle ne bloque ni n'attend les autres. Automatique : au plus tous les `full_scan.interval_days`
  (7 j), quand le Mac est inactif et sur secteur, en QoS background ; une analyse complète terminée, manuelle ou
  automatique, repousse la suivante ; une automatique interrompue est retentée après 20 h. Manuelle : mot de
  passe administrateur (la progression montre tous les chemins, dossiers protégés et autres comptes compris).
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
- **Anti-spyware (Zero Breach Toolkit)** : le scanner Python (lecture seule, hors ligne) et ses indicateurs arrivent
  dans la base signée (`zbt/`), après vérification GPG en CI de la clé de l'éditeur (empreinte épinglée). Le daemon
  le lance chaque semaine (et après un changement d'indicateurs, au plus une fois par jour) avec
  `/usr/bin/python3 -I`, **sous l'identité de l'utilisateur connecté, jamais en root**, en QoS arrière-plan, 30 min max.
- **Posture macOS** : SIP, Gatekeeper, FileVault, coupe-feu, mises à jour de sécurité, XProtect, compte invité, SSH,
  partage d'écran vérifiés chaque jour (outils système, chemins absolus, délais) ; alerte dédupliquée par réglage
  à corriger, résolue automatiquement une fois corrigé (`parabellum posture`, carte « Sécurité de macOS »).
- **DNS en mode fail-open** : si dnscrypt-proxy tombe, le daemon restaure les DNS d'origine pour ne jamais couper Internet.
- **VPN open source plutôt que Shadowrocket** : Shadowrocket n'a ni API ni CLI. Le daemon fait tourner sing-box
  (GPL-3.0, mêmes protocoles) avec une interface TUN et une route stricte, depuis un profil importé (lien de partage,
  abonnement, `.conf` WireGuard) ; les noms d'hôte des serveurs sont résolus à l'avance pour que le kill switch les
  autorise par IP. Un VPN déjà configuré dans macOS (Shadowrocket compris) reste pilotable par `scutil --nc`.
  sing-box ne publie pas de signature vérifiable sur le Mac : la CI vérifie l'attestation de provenance GitHub de la
  release (`gh attestation verify`) et épingle son SHA-256 dans la base signée (`components/pins.json`).
- **Kill switch pf sans toucher à `/etc/pf.conf`** : règles dans l'ancre `com.apple/250.Parabellum` (évaluée par la
  configuration d'Apple), pf activé par jeton (`pfctl -E` / `-X`). Fail-open : l'ancre est vidée quand le daemon
  s'arrête ou quand le VPN n'est plus voulu.
- **Réseaux identifiés par la MAC de leur box** (`gw:<MAC>`) : marche en Ethernet et sans autorisation de localisation
  (que macOS 14+ exige pour lire le nom du Wi-Fi). Base du mode « réseaux non fiables » et de la détection d'ARP spoofing.
  Limite connue : une MAC se copie. Un point d'accès hostile qui reprendrait la MAC LAN de ta box serait pris pour
  ton réseau de confiance (VPN non forcé). Pour les lieux sensibles, préférer le mode « toujours connecté ».
- **VPN déclaré connecté seulement si le trafic passe** : après l'apparition de l'interface TUN, le daemon fait une
  requête HTTPS qui traverse le tunnel ; sans réponse en 30 s, la tentative échoue (pas de faux « connecté » avec un
  mauvais mot de passe ou un serveur éteint) et le kill switch se retire au bout de 45 s s'il n'a jamais été armé.
  Contrôle de santé chaque minute ensuite. Si sing-box plante 5 fois de suite (problème local, pas réseau), le
  kill switch est relâché pour que le Mac et les mises à jour de Parabellum gardent Internet.
- **Actions sur un processus identifiées par pid + heure de démarrage** : arrêter ou reprendre depuis une alerte
  vérifie que le pid désigne encore exactement le même processus (pas de signal à un autre programme qui aurait
  récupéré le pid). Les interpréteurs (python3, node, bash…) ne sont jamais mis en quarantaine, seul le processus
  fautif est arrêté.
- **Instantanés montés hors de portée des utilisateurs** : le snapshot APFS est monté dans le `tmp/` privé du
  daemon (0700), root copie seulement l'élément demandé (aucun lien symbolique suivi) vers une zone de transit, puis
  la copie finale est faite avec les droits de l'utilisateur.
- **Garde comportementale** : événements `eslogger` (exec, open, create, rename) filtrés par chemins sensibles et
  programmes approuvés (binaires Apple, Team ID de la base ou des réglages). Arrêt sur détection sûre ; rançongiciel
  suspendu (SIGSTOP) jusqu'à la décision de l'utilisateur.
- **Texte inerte : règles à l'exécution, pas au repos** : YARA et les heuristiques décrivent ce que fait un malware,
  donc au repos elles se déclenchent sur tout texte qui en parle (nos règles, nos tests, un rapport de sécurité). Les
  fichiers que rien n'exécute seuls (`.rs`, `.swift`, `.yar`, `.json`, `.toml`, `.yaml`, `.md`… sans shebang, hors
  bundle, liste dans `pb-core/src/inert.rs`) ne passent plus les règles au repos ; base de hash et ClamAV s'appliquent
  toujours, et les `.txt` restent analysés. Le seul moyen de les exécuter est de les passer à un interpréteur : quand
  `sh`, `osascript`, `python`… reçoivent un tel fichier en position de script, `eslogger` transmet l'événement (même
  lancé par launchd) et le daemon l'analyse entièrement, tue le processus et met le fichier en quarantaine sur une
  détection sûre. Limite : `sh -c "$(cat x.json)"` ou un chemin relatif ne sont pas couverts par ce mécanisme.
- **Nos propres fichiers reconnus par leur contenu, jamais par leur emplacement** : `make pkg` écrit
  `manifest.json` (SHA-256 de chaque fichier installé, `scripts/build-manifest.sh`). Ces empreintes rejoignent
  l'allowlist du moteur, et la garde ignore ce que font nos binaires vérifiés : un octet changé et le fichier redevient
  un étranger. Le dossier racine reste hors temps réel (journaux, base, quarantaine), mais `bin/`, `signatures/` et
  l'app sont comparés au manifeste toutes les 6 h : fichier modifié, manquant ou inconnu → alerte. Le manifeste n'est
  pas signé à part (la clé release reste hors du job de build) : il hérite de l'authenticité du pkg, et le daemon le
  scelle (version + empreinte + date) : un nouveau manifeste n'est accepté que si le reçu de l'installateur macOS
  (`/var/db/receipts/com.wldeus.parabellum.pkg.plist`, `InstallDate`) est plus récent que le sceau ; sinon alerte
  critique. La version seule ne prouve rien : elle reste `0.1.0` d'un `make pkg` local à l'autre.
- **Verdicts persistants par contenu** : un verdict propre et autonome (aucune détection, aucune erreur, aucune
  dépendance à la signature de code, ClamAV a répondu s'il était demandé) est gardé dans `verdict_cache`, sous une
  clé hash du contenu + typage du fichier + empreinte du moteur (version, base, règles, motifs, modèles, signataires,
  ClamAV) + options. Il survit aux redémarrages et sert pour toutes les copies du même contenu ; une nouvelle base ou
  de nouvelles règles changent l'empreinte, donc tout est réanalysé. Les détections ne sont jamais mises en cache.
- **Aucune signature dans nos binaires** : `scripts/check-no-embedded-signatures.sh` vérifie aussi `parabellumd` et
  `parabellum` (module yara-x `cuckoo` exclu du build), et un test fait passer le dépôt entier sous nos propres règles :
  la moindre détection fait échouer la CI.
- **RGPD sans tiers** : le daemon compose les courriers (FR/EN) et suit les délais ; en mode brouillons, l'app écrit les
  `.eml` dans Téléchargements et Mail les envoie ; en mode SMTP, le daemon envoie avec un quota quotidien.
- **Agent courrier RGPD (modèle local)** : boîte dédiée lue en IMAP (TLS, `EXAMINE` + `BODY.PEEK` : rien n'est
  marqué lu). Chaque réponse est rattachée à sa demande par la référence `[Réf. PB-xxxxxxxx]` de l'objet, notre
  `Message-ID` dans `In-Reply-To`, ou le domaine du courtier s'il est sans ambiguïté ; un échec DKIM/DMARC chez le
  fournisseur l'écarte. Ollama (épinglé dans la base signée, signature Apple Team ID `3MU9H2V9Y9` vérifiée avec
  `codesign` + Gatekeeper) démarre seulement quand le Mac est inactif et qu'un message doit être étiqueté, en
  `nobody`, sur un port loopback aléatoire, et s'arrête dès que tu reprends la main. Le modèle (`qwen3:4b` par
  défaut) ne fait que **classer** dans un schéma JSON à énumération fermée ; un tableau de décision fixe met à jour
  la demande. L'agent n'envoie jamais de mail et ne répond jamais à ta place : pièce d'identité, informations,
  formulaire → statut « à toi de répondre » + alerte. Notes Obsidian (tableau de bord, une note par organisme,
  journal ; section « Mes notes » conservée) écrites par la CLI **en ton nom** ; la base root reste la source de
  vérité, modifier les notes ne peut pas influencer l'agent.
- **Outils locaux exécutés par l'utilisateur** : nettoyage des métadonnées et vérification d'un export de mots de passe
  passent par la CLI lancée par l'app, avec les droits de l'utilisateur, jamais par le daemon root.

Voir aussi : `crates/pb-core/src/ipc.rs` (protocole), `crates/pb-core/src/db.rs` (format de la base),
`docs/INSTALL.md` (build et installation).
