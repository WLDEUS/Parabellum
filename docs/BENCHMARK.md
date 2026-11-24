# PAB-1 — Parabellum Assurance Benchmark (méthodologie)

> Version 1, novembre 2026. Objectif : pouvoir dire, chiffres à l'appui, à quel niveau de test
> Parabellum tient, et ne jamais régresser. Mesures automatiques : `bench/pab.py` (sur le Mac),
> tests `pab_*` et `robustness` (CI). Ce qui demande un labo (VM isolée, échantillons réels,
> équipe rouge) est décrit ici avec la même grille.

## 1. Principes

- **Mesurable** : chaque exigence a une métrique, une cible et une procédure.
- **Reproductible** : corpus datés et hachés, générateurs déterministes, résultats en JSON.
- **Adversarial** : on teste aussi l'outil lui-même (il tourne en root et se met à jour seul).
- **Honnête** : ce qui n'est pas couvert est écrit (§8), un échec obligatoire bloque une version.

## 2. Référentiels repris

| Référentiel | Ce qu'on en reprend |
|---|---|
| AV-Comparatives, *Mac Security Test* (2025 : 899 malwares Mac, 750 PUA, 500 Windows, faux positifs sur apps saines) | Batterie A (détection) et C (faux positifs), corpus Mac prévalents |
| AV-TEST, modules macOS (protection, performance, utilisabilité) | Batterie F (performance) |
| NSS Labs, *Advanced Endpoint Protection* 1.0/2.0 (méthode publique : efficacité par vecteur, **évasion**, faux positifs, coût) | Batterie B (évasion) et E (résilience) |
| MITRE ATT&CK for macOS + Atomic Red Team (Red Canary) | Batterie D (comportement), une ligne par technique |
| ANSSI, CSPN (*Critères pour l'évaluation*, CER-P-02 v5.0) : cible de sécurité, conformité, analyse de vulnérabilité, tests de pénétration en temps contraint | Batterie G (assurance), niveau N3 |
| NIAP, *Protection Profile for Application Software* v2.0 (FCS, FDP, FMT, FPR, FPT, FTP) | Grille d'exigences de la batterie G |
| AMTSO (plans de test publiés) | Forme du plan de test et du rapport |

NSS Labs a fermé en 2020 ; sa méthode AEP reste publique et sert de grille pour l'évasion et la
résilience.

## 3. Modèle de menace

| Adversaire | Exemples | Attendu |
|---|---|---|
| A1 Malware de masse | voleurs AMOS / Atomic, Cuckoo, adwares, faux installeurs | **Prévenir** : détecté avant ou à l'exécution, quarantaine |
| A2 Criminel ciblé | variante repackagée, chargeur script, persistance discrète | **Détecter** : alerte sur comportement ou persistance en minutes |
| A3 Acteur étatique | logiciels espions (Pegasus, Predator, Graphite), 0-day noyau | **Témoigner** : traces (ZBT, IOC, intégrité), jamais de fausse assurance |
| A4 Attaque de l'outil | binaire tiers qui parle à la socket, fichier piégé pour le parseur root, base de menaces rejouée, dépendance piégée | **Résister** : refus, pas de plantage, pas d'élévation |

Hors portée assumée : un attaquant déjà root peut tout neutraliser (on vise sa **détection** par le
contrôle d'intégrité), le firmware, le matériel.

## 4. Niveaux

| Niveau | Équivalent | Exigé |
|---|---|---|
| **N1 Labo grand public** | AV-Comparatives Mac certifié | A ≥ 99 % malwares Mac prévalents, C = 0 FP sur le corpus labo, F dans les cibles |
| **N2 Entreprise** | NSS AEP « Recommended » | N1 + B 100 % des variantes obligatoires, D ≥ 80 % des techniques détectées, E sans échec |
| **N3 Haute assurance** | CSPN / profil NIAP, standard des administrations | N2 + G complet : cible de sécurité, revue de code, fuzzing continu, revue crypto, test d'intrusion externe, chaîne d'approvisionnement vérifiable |

## 5. Batteries

### A. Efficacité de détection
- **Corpus** : échantillons macOS MalwareBazaar (Mach-O, DMG, PKG, scripts) des 30 derniers jours,
  + prévalents de l'année ; PUA à part. Jamais sur le Mac principal : VM isolée, réseau coupé.
- **Mesure** : `PAB_I_AM_IN_A_VM=1 python3 bench/pab.py efficacy <dossier>` (statique, sans exécution,
  `scan --report-only`) ; à l'exécution : lancer dans la VM avec la protection temps réel.
- **Cibles** : statique ≥ 99 % (N1) ; délai apparition d'une famille → règle < 24 h (N3, pipeline nocturne).

### B. Évasion (NSS AEP)
| Variante | Obligatoire | Automatisé |
|---|---|---|
| EICAR renommé (.jpg), sans extension | oui | CI `pab_evasion_must_detect_variants` + `pab.py evasion` |
| ZIP, ZIP imbriqué ×3, tar.gz, gzip | oui | idem |
| Image disque DMG (UDZO) | oui | `pab.py evasion` (macOS) |
| ZIP imbriqué ×8 (au-delà de la profondeur max.), EICAR en fin de PDF, base64 dans un script | non (information) | `pab.py evasion` |
| Mach-O repackagé / packé, script obfusqué, *living off the land* (`curl | sh`, `osascript`) | N2 | VM + échantillons |

### C. Faux positifs
- **Corpus** : `/Applications`, apps du Mac App Store, Homebrew, outils de dev (≥ 10 000 fichiers).
- **Mesure** : `python3 bench/pab.py fp` (`sudo` pour `/Applications`, `--report-only` : aucune app touchée).
- **Cibles** : < 0,1 % sur le corpus large ; 0 sur le corpus labo ; **0 blocage d'un outil système**.

### D. Comportement (ATT&CK macOS)
| Technique | Test | Automatisé |
|---|---|---|
| T1543.001 Launch Agent | plist jamais chargé dans `~/Library/LaunchAgents` → alerte | `pab.py behavior` |
| T1543.004 Launch Daemon, T1547.015 éléments d'ouverture | Atomic Red Team | VM |
| T1555.001 Trousseau, T1539 cookies, T1005 wallets | Atomic + leurres | VM |
| T1059.002 AppleScript, T1056.002 faux dialogue de mot de passe | Atomic | VM |
| T1553.001 contournement Gatekeeper (`xattr -d com.apple.quarantine`) | Atomic | VM |
| T1486 chiffrement de masse (rançongiciel) | outil de test maison en VM | VM |
| T1562.001 désactivation de l'outil | batterie E | local |
Score par technique : bloqué / alerté / journalisé / manqué.

### E. Résilience et auto-protection
Automatisé (`pab.py tamper`, non destructif) : socket `root:admin 0660` ; commande modifiante depuis
un binaire tiers → `permission_denied` ; jeton d'administration forgé refusé ; données sensibles
refusées à un tiers ; trame géante sans plantage ; écriture refusée dans `bin/`, `db/`, manifeste ;
signal au daemon refusé ; signatures + runtime renforcé ; base signée de moins de 48 h ; aucune alerte
d'intégrité ouverte. En CI : tâche interne qui panique → redémarrage + alerte
(`panicking_task_is_reported_by_the_supervisor`) ; base plus ancienne refusée (`full_update_rollback_and_downgrade`).
En labo (N2/N3) : tuer / décharger le daemon en root (détection au redémarrage), réécrire la base,
bloquer les mises à jour (gel : alerte via le rapport du jour au-delà de 48 h), DNS détourné.

### F. Performance
| Mesure | Cible | Outil |
|---|---|---|
| CPU au repos (moyenne) | < 1 % d'un cœur | `pab.py perf` |
| RAM au repos | < 150 Mo | `pab.py perf` |
| Latence d'analyse p95, fichier < 10 Mo | < 200 ms | `pab.py perf` |
| Instances de l'app | 1 | `pab.py perf` |
| Copie, installation, lancement d'app, téléchargement (AV-TEST) | < +10 % vs sans Parabellum | VM, protocole AV-TEST |

### G. Assurance (CSPN / NIAP)
| Exigence | Preuve |
|---|---|
| Cible de sécurité (périmètre, menaces, fonctions) | ce document §3 + docs/ARCHITECTURE.md |
| Robustesse des parseurs face aux entrées hostiles | `pb-monitor/tests/robustness.rs`, `pb-engine` `engine_survives_mutated_*` ; long : `PB_FUZZ_ITERS=300000` |
| Crypto (FCS) : Ed25519 minisign (base, mises à jour), AES-256 APFS (coffres), P-256 Secure Enclave (Touch ID) | revue §7 de docs/REVIEW-2026-11.md |
| Contrôle d'accès IPC (FDP/FMT) : jeton d'audit du pair, chemin de l'exécutable, droit d'administration | `ipc.rs` tests `access_decisions` + `pab.py tamper` |
| Vie privée (FPR) : rien n'est envoyé, résumé IA local, données d'alertes jamais au modèle | `daily.rs` tests `prompt_has_no_titles_or_paths` |
| Mises à jour de confiance (FPT_TUD) : signature avant décompression, retour arrière, anti-rétrogradation | tests `pb-updater` |
| Chaîne d'approvisionnement : actions épinglées, cargo-deny, verrous Python hachés, signature dans un job isolé | `supply-chain.yml`, docs/SECURITY-SUPPLY-CHAIN.md, zizmor |
| Analyse de vulnérabilité + test d'intrusion externe (temps contraint) | N3 : à faire réaliser (CESTI ou équivalent) |

## 6. Notation et règle de version

- `bench/pab.py` écrit `bench-results/<date>/scorecard.{json,md}` ; ✅ tenu, ❌ échec, · information.
- **Bloquant** : un échec sur une variante obligatoire (B), un faux positif sur outil système (C), un
  échec de la batterie E, ou une régression de plus de 20 % sur F.
- Chaque version publiée garde sa fiche de score dans la release.

## 7. Où tourne quoi

| Où | Quoi |
|---|---|
| CI à chaque PR | tests `pab_*`, `robustness`, `engine_survives_*`, supervision, cargo-deny, zizmor |
| Mac (avant chaque install majeure) | `python3 bench/pab.py all` puis `python3 bench/pab.py fp` |
| VM isolée (mensuel) | batterie A avec échantillons du mois, Atomic Red Team (D), résilience root (E) |
| Externe (N3) | test d'intrusion de l'outil (socket, parseurs, mise à jour, installeur) |

## 8. Limites connues du produit (à garder visibles)

- Pas d'entitlement Endpoint Security : arrêt **après** lancement (eslogger), pas de blocage avant.
- Signature ad hoc / certificat local, pas de notarisation Apple.
- Les parseurs d'archives, Mach-O et YARA-X tournent dans le daemon root (fuzzés, bornés, mais une
  isolation dans un processus non privilégié reste la mesure N3 la plus importante).
- Un attaquant root peut désactiver l'outil ; seule sa détection est visée.
