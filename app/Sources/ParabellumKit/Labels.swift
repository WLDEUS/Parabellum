import Foundation

// French user-facing labels for every enum shown in the UI.

extension Verdict {
    public var label: String {
        switch self {
        case .clean: return String(localized: "Sain")
        case .suspicious: return String(localized: "Suspect")
        case .malicious: return String(localized: "Malveillant")
        case .unknown: return String(localized: "Inconnu")
        }
    }
}

extension Severity {
    public var label: String {
        switch self {
        case .info: return String(localized: "Info")
        case .low: return String(localized: "Faible")
        case .medium: return String(localized: "Moyenne")
        case .high: return String(localized: "Élevée")
        case .critical: return String(localized: "Critique")
        case .unknown: return String(localized: "Inconnue")
        }
    }
}

extension DetectionEngine {
    public var label: String {
        switch self {
        case .hashDb: return String(localized: "Base de hash")
        case .clamav: return String(localized: "ClamAV")
        case .yara: return String(localized: "YARA")
        case .ml: return String(localized: "Modèle ML")
        case .heuristic: return String(localized: "Heuristique")
        case .virusTotal: return String(localized: "VirusTotal")
        case .unknown: return String(localized: "Moteur inconnu")
        }
    }
}

extension FileKind {
    public var label: String {
        switch self {
        case .macho: return String(localized: "Exécutable Mach-O")
        case .fatMacho: return String(localized: "Mach-O universel")
        case .dmg: return String(localized: "Image disque (DMG)")
        case .pkg: return String(localized: "Paquet d'installation (PKG)")
        case .zip: return String(localized: "Archive ZIP")
        case .script: return String(localized: "Script")
        case .appBundle: return String(localized: "Application")
        case .document: return String(localized: "Document")
        case .archive: return String(localized: "Archive")
        case .other: return String(localized: "Autre")
        }
    }
}

extension ScanOrigin {
    public var label: String {
        switch self {
        case .manual: return String(localized: "Manuelle")
        case .downloads: return String(localized: "Téléchargements")
        case .volume: return String(localized: "Volume externe")
        case .realtime: return String(localized: "Temps réel")
        case .scheduled: return String(localized: "Complète (automatique)")
        case .retroHunt: return String(localized: "Rétro-chasse")
        case .spyware: return String(localized: "Anti-spyware")
        case .fullScan: return String(localized: "Complète")
        case .unknown: return String(localized: "Autre")
        }
    }
}

extension JobState {
    public var label: String {
        switch self {
        case .queued: return String(localized: "En attente")
        case .running: return String(localized: "En cours")
        case .finished: return String(localized: "Terminée")
        case .cancelled: return String(localized: "Annulée")
        case .failed: return String(localized: "Échec")
        case .unknown: return String(localized: "Inconnu")
        }
    }
}

extension AlertKind {
    public var label: String {
        switch self {
        case .malware: return String(localized: "Malware")
        case .suspicious: return String(localized: "Fichier suspect")
        case .persistence: return String(localized: "Persistance")
        case .device: return String(localized: "Périphérique")
        case .network: return String(localized: "Réseau")
        case .update: return String(localized: "Mise à jour")
        case .system: return String(localized: "Système")
        case .behavior: return String(localized: "Comportement")
        case .privacy: return String(localized: "Vie privée")
        case .unknown: return String(localized: "Autre")
        }
    }
}

extension AlertStatus {
    public var label: String {
        switch self {
        case .open: return String(localized: "Ouverte")
        case .acknowledged: return String(localized: "Vue")
        case .resolved: return String(localized: "Résolue")
        case .unknown: return String(localized: "Inconnu")
        }
    }
}

extension AlertAction {
    public var label: String {
        switch self {
        case .acknowledge: return String(localized: "Marquer comme vue")
        case .quarantine: return String(localized: "Mettre en quarantaine")
        case .allow: return String(localized: "Autoriser")
        case .restore: return String(localized: "Restaurer")
        case .trustDevice: return String(localized: "Faire confiance")
        case .blockDevice: return String(localized: "Bloquer")
        case .approvePersistence: return String(localized: "Approuver")
        case .removePersistence: return String(localized: "Supprimer l'élément")
        case .reportFalsePositive: return String(localized: "Signaler un faux positif")
        case .dismiss: return String(localized: "Ignorer")
        case .killProcess: return String(localized: "Arrêter le processus")
        case .resumeProcess: return String(localized: "Reprendre le processus")
        case .trustNetwork: return String(localized: "Faire confiance à ce réseau")
        case .allowDomain: return String(localized: "Autoriser ce domaine")
        case .markNormal: return String(localized: "C'est normal")
        case .trustLanDevice: return String(localized: "Je connais cet appareil")
        case .enableTravelMode: return String(localized: "Activer le mode Voyage")
        case .unknown: return String(localized: "Action inconnue")
        }
    }

    /// Changes something irreversible-looking: ask for confirmation in the UI.
    public var isDestructive: Bool {
        switch self {
        case .quarantine, .removePersistence, .blockDevice, .killProcess:
            return true
        default:
            return false
        }
    }
}

extension DeviceKind {
    /// Section title (plural).
    public var label: String {
        switch self {
        case .volume: return String(localized: "Volumes")
        case .hid: return String(localized: "Claviers, souris et HID")
        case .usb: return String(localized: "Autres périphériques USB")
        case .bluetooth: return String(localized: "Bluetooth")
        case .networkInterface: return String(localized: "Interfaces réseau")
        case .thunderbolt: return String(localized: "Thunderbolt")
        case .wifiNetwork: return String(localized: "Réseaux Wi-Fi")
        case .unknown: return String(localized: "Autres")
        }
    }
}

extension DeviceTrust {
    public var label: String {
        switch self {
        case .unknown: return String(localized: "Non vérifié")
        case .trusted: return String(localized: "De confiance")
        case .blocked: return String(localized: "Bloqué")
        }
    }
}

extension DeviceChange {
    public var label: String {
        switch self {
        case .new: return String(localized: "Nouveau")
        case .connected: return String(localized: "Connecté")
        case .disconnected: return String(localized: "Déconnecté")
        case .unknown: return String(localized: "Inconnu")
        }
    }
}

extension PersistenceKind {
    public var label: String {
        switch self {
        case .launchAgent: return String(localized: "LaunchAgent")
        case .launchDaemon: return String(localized: "LaunchDaemon")
        case .loginItem: return String(localized: "Élément de connexion")
        case .backgroundItem: return String(localized: "Élément d'arrière-plan")
        case .cron: return String(localized: "Tâche cron")
        case .periodic: return String(localized: "Script periodic")
        case .shellProfile: return String(localized: "Profil shell")
        case .configurationProfile: return String(localized: "Profil de configuration")
        case .browserExtension: return String(localized: "Extension de navigateur")
        case .systemExtension: return String(localized: "Extension système")
        case .kernelExtension: return String(localized: "Extension du noyau")
        case .authorizationPlugin: return String(localized: "Plugin d'autorisation")
        case .other: return String(localized: "Autre")
        }
    }
}

extension PersistenceStatus {
    public var label: String {
        switch self {
        case .baseline: return String(localized: "Présent à l'installation")
        case .new: return String(localized: "Nouveau")
        case .approved: return String(localized: "Approuvé")
        case .removed: return String(localized: "Supprimé")
        case .quarantined: return String(localized: "En quarantaine")
        case .unknown: return String(localized: "Inconnu")
        }
    }
}

extension ComponentState {
    public var label: String {
        switch self {
        case .notInstalled: return String(localized: "Non installé")
        case .installed: return String(localized: "À jour")
        case .updateAvailable: return String(localized: "Mise à jour disponible")
        case .updating: return String(localized: "Mise à jour…")
        case .error: return String(localized: "Erreur")
        case .disabled: return String(localized: "Désactivé")
        case .needsUserAction: return String(localized: "Action requise")
        case .unknown: return String(localized: "Inconnu")
        }
    }
}

extension UpdateTarget {
    public var label: String {
        switch self {
        case .db: return String(localized: "Base de menaces")
        case .components: return String(localized: "Composants")
        case .app: return String(localized: "Application")
        case .all: return String(localized: "Tout")
        case .unknown: return String(localized: "Inconnu")
        }
    }
}

extension ExtensionState {
    public var label: String {
        switch self {
        case .notInstalled: return String(localized: "Non installée")
        case .installedDisabled: return String(localized: "Installée mais désactivée")
        case .enabled: return String(localized: "Activée")
        case .unknown: return String(localized: "État inconnu")
        }
    }
}

extension ProtectionState {
    public var label: String {
        switch self {
        case .active: return String(localized: "Protection active")
        case .paused: return String(localized: "Protection en pause")
        case .degraded: return String(localized: "Protection dégradée")
        case .unknown: return String(localized: "État inconnu")
        }
    }
}

extension ErrorCode {
    public var label: String {
        switch self {
        case .badRequest: return String(localized: "Requête invalide")
        case .notFound: return String(localized: "Introuvable")
        case .permissionDenied: return String(localized: "Permission refusée")
        case .authRequired: return String(localized: "Autorisation administrateur requise")
        case .busy: return String(localized: "Service occupé")
        case .unavailable: return String(localized: "Indisponible")
        case .internalError: return String(localized: "Erreur interne")
        case .unknown: return String(localized: "Erreur")
        }
    }
}

// MARK: - VPN, behaviour guard, privacy

extension VpnState {
    public var label: String {
        switch self {
        case .disconnected: return String(localized: "Déconnecté")
        case .connecting: return String(localized: "Connexion…")
        case .connected: return String(localized: "Connecté")
        case .disconnecting: return String(localized: "Déconnexion…")
        case .error: return String(localized: "Erreur")
        case .unknown: return String(localized: "État inconnu")
        }
    }
}

extension KillSwitchState {
    public var label: String {
        switch self {
        case .off: return String(localized: "Désactivé")
        case .armed: return String(localized: "Armé")
        case .blocking: return String(localized: "Internet bloqué (tunnel coupé)")
        case .error: return String(localized: "Erreur")
        case .unknown: return String(localized: "État inconnu")
        }
    }
}

extension VpnMode {
    public var label: String {
        switch self {
        case .off: return String(localized: "Manuel")
        case .always: return String(localized: "Toujours connecté")
        case .untrustedNetworks: return String(localized: "Sur les réseaux non fiables")
        }
    }
}

extension VpnBackend {
    public var label: String {
        switch self {
        case .singBox: return String(localized: "sing-box (géré par Parabellum)")
        case .external: return String(localized: "VPN déjà configuré dans macOS")
        }
    }
}

extension SendMode {
    public var label: String {
        switch self {
        case .drafts: return String(localized: "Brouillons ouverts dans Mail (tu envoies)")
        case .smtp: return String(localized: "Envoi automatique par SMTP")
        }
    }
}

extension BreachProvider {
    public var label: String {
        switch self {
        case .xposedOrNot: return String(localized: "XposedOrNot (gratuit)")
        case .hibp: return String(localized: "Have I Been Pwned (clé payante)")
        }
    }
}

extension AliasProvider {
    public var label: String {
        switch self {
        case .disabled: return String(localized: "Aucun")
        case .addy: return "addy.io"
        case .simpleLogin: return String(localized: "SimpleLogin")
        }
    }
}

extension RemovalStatus {
    public var label: String {
        switch self {
        case .queued: return String(localized: "En file d'attente")
        case .draftReady: return String(localized: "Brouillon prêt")
        case .sent: return String(localized: "Envoyée")
        case .reminded: return String(localized: "Relancée")
        case .escalated: return String(localized: "Sans réponse (CNIL)")
        case .completed: return String(localized: "Effacement confirmé")
        case .refused: return String(localized: "Refusée")
        case .needsForm: return String(localized: "Formulaire web")
        case .needsYou: return String(localized: "À toi de répondre")
        case .failed: return String(localized: "Échec d'envoi")
        case .unknown: return String(localized: "Inconnu")
        }
    }
}

public enum PrivacyLabels {
    /// Broker region code → French label.
    public static func region(_ code: String) -> String {
        switch code {
        case "eu": return "Europe"
        case "global": return "International"
        case "us": return String(localized: "États-Unis")
        default: return code
        }
    }

    /// Leak-test check id → French label.
    public static func leakCheck(_ id: String) -> String {
        switch id {
        case "tunnel": return "Tunnel"
        case "ipv4": return "IPv4"
        case "ipv6": return "IPv6"
        case "dns": return "DNS"
        case "kill_switch": return "Kill switch"
        default: return id
        }
    }
}
